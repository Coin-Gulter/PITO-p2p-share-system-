# p2pshare/shared/discovery.py

from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceStateChange
from threading import Thread, Lock, Event
import socket
import time
import netifaces
from shared.config import settings
from shared.logging_config import setup_logger

# Set up logger
logger = setup_logger(__name__)

SERVICE_TYPE = "_p2pshare._tcp.local."
# Add instance-specific service name to avoid conflicts on same machine
SERVICE_NAME = f"{settings.device_id}-{socket.gethostname()}.{SERVICE_TYPE}"

def get_network_interfaces():
    """Get all available network interfaces that are up and have an IP address"""
    interfaces = []
    try:
        # First try to get all interfaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:  # Has IPv4 address
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and not addr['addr'].startswith('127.'):
                        interfaces.append((iface, addr['addr']))
                        logger.debug(f"Found interface {iface} with address {addr['addr']}")
        
        # If no interfaces found, try localhost
        if not interfaces:
            interfaces.append(('lo', '127.0.0.1'))
            logger.debug("No external interfaces found, using localhost")
            
        return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {str(e)}", exc_info=True)
        # Fallback to localhost
        return [('lo', '127.0.0.1')]

def get_local_ip():
    """Get the best local IP address for service discovery"""
    try:
        # First try to get all interfaces
        interfaces = get_network_interfaces()
        if interfaces:
            # Prefer non-loopback interfaces
            for iface, addr in interfaces:
                if not addr.startswith('127.'):
                    logger.info(f"Using interface {iface} with address {addr}")
                    return addr
            
            # Fallback to first interface if all are loopback
            return interfaces[0][1]
            
        # Fallback to old method if no interfaces found
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Try to connect to a public DNS server
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            logger.info(f"Using fallback IP address: {ip}")
            return ip
        except Exception:
            # If that fails, use localhost
            logger.warning("Could not determine external IP, using localhost")
            return "127.0.0.1"
        finally:
            s.close()
    except Exception as e:
        logger.warning(f"Failed to get local IP: {str(e)}", exc_info=True)
        return "127.0.0.1"

class PeerDiscovery:
    def __init__(self, port: int):
        self.zeroconf = None  # Initialize as None
        self.port = port
        self.peers = {}  # {device_id: (ip, port)}
        self.browser = None
        self._peers_lock = Lock()
        self._stop_event = Event()
        self._service_info = None  # Store our service info
        self._known_services = set()  # Track known services
        self._loop = None  # Store event loop
        # Create unique instance ID for this discovery instance
        self._instance_id = f"{settings.device_id}-{port}"
        logger.info(f"Initialized PeerDiscovery on port {port} with instance ID {self._instance_id}")

    def get_peers(self):
        """Get current peers with a refresh of the service list"""
        try:
            # Only attempt refresh if zeroconf is active
            if self.zeroconf and not self._stop_event.is_set() and self._service_info:
                try:
                    services = self.zeroconf.get_service_info(SERVICE_TYPE, self._service_info.name)
                    if services:
                        self._process_added_service_info(SERVICE_TYPE, self._service_info.name, self.zeroconf)
                except Exception as e:
                    logger.debug(f"Error refreshing service list: {e}")
        except Exception as e:
            logger.debug(f"Error in get_peers: {e}")
            
        with self._peers_lock:
            return dict(self.peers)

    def register_service(self):
        """Register the service with improved reliability"""
        try:
            if self.zeroconf is None:
                self.zeroconf = Zeroconf()
                self._loop = self.zeroconf.loop

            # Get current IP
            ip = get_local_ip()
            if ip == "127.0.0.1":
                logger.warning("Using loopback address - discovery may be limited to local machine")

            # Create unique service name for this instance with timestamp to avoid conflicts
            timestamp = int(time.time())
            service_name = f"{self._instance_id}-{timestamp}.{SERVICE_TYPE}"
            
            logger.info(f"Registering service: {service_name} on {ip}:{self.port}")
            
            # Create service info with minimal properties
            self._service_info = ServiceInfo(
                SERVICE_TYPE,
                service_name,
                addresses=[socket.inet_aton(ip)],
                port=self.port,
                properties={
                    "id": settings.device_id.encode(),
                    "instance_id": self._instance_id.encode(),
                    "port": str(self.port).encode(),
                    "hostname": socket.gethostname().encode(),
                    "timestamp": str(timestamp).encode()  # Add timestamp for freshness
                },
            )
            
            # Register service with retry and proper cleanup
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    if not self._stop_event.is_set():
                        # Unregister any existing service first
                        if self._service_info:
                            try:
                                self.zeroconf.unregister_service(self._service_info)
                            except Exception as e:
                                logger.debug(f"Error unregistering existing service: {e}")
                        
                        # Wait a moment before registering new service
                        time.sleep(0.5)
                        
                        self.zeroconf.register_service(self._service_info)
                        logger.info(f"Service registered successfully: {service_name}")
                        return True
                except Exception as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"Registration attempt {attempt + 1} failed: {e}, retrying...")
                        time.sleep(1)  # Wait before retry
                    else:
                        raise
            
        except Exception as e:
            logger.error(f"Error registering service: {str(e)}", exc_info=True)
            # Clean up zeroconf on registration failure
            if self.zeroconf:
                try:
                    self.zeroconf.close()
                except Exception as cleanup_error:
                    logger.debug(f"Error during zeroconf cleanup: {cleanup_error}")
                self.zeroconf = None
                self._loop = None
            return False

    def browse(self):
        """Start browsing for services with improved reliability"""
        if self._stop_event.is_set():
            logger.warning("Cannot start browsing - service is stopping")
            return False

        logger.info(f"Starting to browse for services of type: {SERVICE_TYPE}")
        
        try:
            # Cancel existing browser if any
            if self.browser:
                try:
                    self.browser.cancel()
                    # Wait a short time for the browser to fully cancel
                    time.sleep(0.1)
                except Exception as e:
                    logger.debug(f"Error canceling existing browser: {e}")
                finally:
                    self.browser = None
            
            # Clear known services
            self._known_services.clear()
            
            # Create a handler function that matches the expected signature
            def on_service_state_change(zeroconf, service_type, name, state_change):
                if not self._stop_event.is_set():
                    self._on_service_state_change(zeroconf, service_type, name, state_change)
            
            # Start new browser with the wrapped handler
            self.browser = ServiceBrowser(
                self.zeroconf,
                SERVICE_TYPE,
                handlers=[on_service_state_change]
            )
            logger.info("Service browser started")
            
            # Force an immediate browse of all services
            try:
                # Use get_service_info instead of get_service_info_list
                services = self.zeroconf.get_service_info(SERVICE_TYPE, self._service_info.name)
                if services:
                    self._process_added_service_info(SERVICE_TYPE, self._service_info.name, self.zeroconf)
            except Exception as e:
                logger.debug(f"Error during initial service browse: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting service browser: {e}", exc_info=True)
            return False

    def _process_added_service_info(self, service_type: str, name: str, zeroconf_instance: Zeroconf):
        """Process a newly added service with improved reliability"""
        try:
            info = zeroconf_instance.get_service_info(service_type, name)
            if not info:
                logger.debug(f"No service info found for {name}")
                return

            # Get basic service properties
            device_id = info.properties.get(b"id", b"").decode()
            instance_id = info.properties.get(b"instance_id", b"").decode()
            port_str = info.properties.get(b"port", b"").decode()
            hostname = info.properties.get(b"hostname", b"").decode()
            timestamp = int(info.properties.get(b"timestamp", b"0").decode())
            
            # Skip if this is our own instance
            if instance_id == self._instance_id:
                logger.debug(f"Ignoring self instance: {instance_id}")
                return
                
            parsed_addresses = info.parsed_addresses()
            if not parsed_addresses:
                logger.warning(f"No addresses found for service {name}")
                return
                
            ip = parsed_addresses[0]
            port = int(port_str) if port_str else info.port
            
            if device_id:
                # Check if service is fresh (within last 60 seconds)
                if time.time() - timestamp > 60:
                    logger.debug(f"Ignoring stale service: {device_id} (timestamp: {timestamp})")
                    return
                    
                logger.info(f"Found new peer: {device_id} at {ip}:{port} (instance: {instance_id})")
                with self._peers_lock:
                    self.peers[device_id] = (ip, port)
                    self._known_services.add(name)
                    logger.debug(f"Updated peers dict: {self.peers}")
                
        except Exception as e:
            logger.error(f"Error processing service info: {str(e)}", exc_info=True)

    def _on_service_state_change(self, zeroconf_instance: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange):
        """Handle service state changes with improved reliability"""
        if self._stop_event.is_set():
            return

        logger.debug(f"Service state change: {name} - {state_change}")
        
        try:
            if state_change == ServiceStateChange.Removed:
                try:
                    # Extract device ID from service name
                    device_id = name.split('.')[0]  # Handle new name format
                    with self._peers_lock:
                        if device_id in self.peers:
                            logger.info(f"Peer removed: {device_id}")
                            del self.peers[device_id]
                            self._known_services.discard(name)
                            logger.debug(f"Updated peers dict after removal: {self.peers}")
                except Exception as e:
                    logger.error(f"Error processing service removal: {str(e)}", exc_info=True)
            
            elif state_change == ServiceStateChange.Added:
                self._process_added_service_info(service_type, name, zeroconf_instance)
                
            elif state_change == ServiceStateChange.Updated:
                # Handle service updates (e.g., new timestamp)
                self._process_added_service_info(service_type, name, zeroconf_instance)
        except Exception as e:
            logger.error(f"Error in service state change handler: {str(e)}", exc_info=True)

    def run(self):
        """Run the discovery service with improved reliability"""
        logger.info(f"Starting discovery service with device_id: {settings.device_id}")
        
        try:
            # Initialize Zeroconf if not already done
            if self.zeroconf is None:
                self.zeroconf = Zeroconf()
                self._loop = self.zeroconf.loop

            # Register and browse
            if not self.register_service():
                logger.error("Failed to register service")
                return
                
            # Small delay to ensure registration is complete
            time.sleep(1)
                
            if not self.browse():
                logger.error("Failed to start service browser")
                return
                
            logger.info("Discovery service started")
            
            # Run loop with periodic re-registration and cleanup
            last_register_time = time.time()
            last_cleanup_time = time.time()
            registration_failures = 0
            max_failures = 3
            
            while not self._stop_event.is_set():
                try:
                    current_time = time.time()
                    
                    # Re-register service every 30 seconds to maintain presence
                    if current_time - last_register_time > 30:
                        if self.register_service():
                            last_register_time = current_time
                            registration_failures = 0  # Reset failure counter on success
                            # Force a refresh of known services after re-registration
                            self.browse()
                        else:
                            registration_failures += 1
                            if registration_failures >= max_failures:
                                logger.error("Too many registration failures, restarting discovery")
                                # Clean up and reinitialize
                                self.unregister()
                                time.sleep(1)
                                if not self._stop_event.is_set():
                                    self.zeroconf = None
                                    self._loop = None
                                    self.run()  # Restart discovery
                                return
                    
                    # Clean up stale peers every 60 seconds
                    if current_time - last_cleanup_time > 60:
                        with self._peers_lock:
                            current_peers = dict(self.peers)
                            for device_id, (ip, port) in current_peers.items():
                                try:
                                    # Try to get fresh service info
                                    service_name = f"{device_id}.{SERVICE_TYPE}"
                                    info = self.zeroconf.get_service_info(SERVICE_TYPE, service_name)
                                    if not info:
                                        logger.info(f"Removing stale peer: {device_id}")
                                        del self.peers[device_id]
                                except Exception:
                                    logger.debug(f"Error checking peer {device_id}, removing")
                                    del self.peers[device_id]
                            last_cleanup_time = current_time
                    
                    self._stop_event.wait(timeout=5)
                    if not self._stop_event.is_set():
                        logger.debug(f"Current peers: {self.get_peers()}")
                except Exception as e:
                    logger.error(f"Error in discovery loop: {e}", exc_info=True)
                    if not self._stop_event.is_set():
                        time.sleep(5)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Error in discovery service: {str(e)}", exc_info=True)
        finally:
            self.unregister()

    def unregister(self):
        """Unregister services with improved cleanup"""
        logger.info("Attempting to unregister services and close zeroconf.")
        self._stop_event.set()
        
        # Cancel browser first and wait for it to fully stop
        if self.browser:
            try:
                self.browser.cancel()
                logger.info("Service browser canceled.")
                # Give the browser time to fully cancel
                time.sleep(0.2)
            except Exception as e:
                logger.debug(f"Error canceling browser: {e}")
            finally:
                self.browser = None
        
        # Store reference to zeroconf before clearing
        zeroconf = self.zeroconf
        self.zeroconf = None
        self._loop = None
        self._service_info = None
        
        if zeroconf:
            try:
                # Unregister service without timeout
                if self._service_info:
                    try:
                        zeroconf.unregister_service(self._service_info)
                        logger.info("Service unregistered.")
                    except Exception as e:
                        logger.debug(f"Error during service unregistration: {e}")
                
                # Close zeroconf without timeout
                try:
                    zeroconf.close()
                    logger.info("Zeroconf closed.")
                except Exception as e:
                    logger.debug(f"Error during zeroconf close: {e}")
                
            except Exception as e:
                logger.error(f"Error during cleanup: {e}", exc_info=True)


if __name__ == "__main__":
    discovery = PeerDiscovery(port=settings.http_port)
    thread = Thread(target=discovery.run, daemon=True)
    thread.start()
    logger.info("Discovery started. Press Ctrl+C to stop.")
    try:
        while thread.is_alive():
            thread.join(timeout=1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received in main, stopping discovery.")
        discovery.unregister()
        thread.join(timeout=5)
        if thread.is_alive():
            logger.warning("Discovery thread did not stop gracefully after unregister.")
    except Exception as e:
        logger.error(f"Exception in main: {e}", exc_info=True)
        discovery.unregister()
        thread.join(timeout=5)
    finally:
        logger.info("Application finished.")
