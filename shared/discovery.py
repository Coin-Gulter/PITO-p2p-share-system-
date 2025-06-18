import socket
import time
import json
import logging
import asyncio
import threading
import uuid # For generating unique device IDs

from zeroconf import ServiceInfo, ServiceBrowser, Zeroconf, ServiceStateChange
from typing import Dict, Tuple

# Set up logger
logger = logging.getLogger(__name__)
# Configure logging for better visibility during testing
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Constants
SERVICE_TYPE = "_p2pshare._tcp.local."
# TTL_SECONDS = 60 * 5 # 5 minutes # Retained for clarity, but not passed to ServiceInfo init

class PeerDiscovery:
    def __init__(self, port: int, device_id: str): # Added device_id to init
        self.port = port
        self.device_id = device_id
        # Unique instance name per run, incorporating device_id and port for clarity
        self.instance_name = f"{device_id}-{port}-{int(time.time())}"
        self.peers: Dict[str, Tuple[str, int]] = {} # {device_id: (ip, port)}
        self.service_info: ServiceInfo | None = None
        self.zeroconf_instance: Zeroconf | None = None
        self.browser: ServiceBrowser | None = None
        self._is_running = False
        self._browser_task = None
        self._loop = None # Stores the asyncio event loop for this instance

        logger.info(f"Initialized PeerDiscovery on port {self.port} with instance ID {self.instance_name}")

    def _get_local_ip(self):
        """Attempts to get the local IP address."""
        try:
            # Create a socket connection to an external server (e.g., Google's DNS)
            # This doesn't actually send data, just finds the local IP used for external connections.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # Connect to a public DNS server
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            try:
                # Fallback to hostname if direct connection fails
                return socket.gethostbyname(socket.gethostname())
            except Exception as e:
                logger.error(f"Could not determine local IP address: {e}")
                return "127.0.0.1" # Fallback to loopback if all else fails

    def _on_service_state_change(self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange):
        """Callback for Zeroconf service state changes."""
        logger.info(f"Service state change detected: {name} - {state_change.name}") # Log all state changes at INFO level

        if state_change == ServiceStateChange.Added:
            # Crucially, use call_soon_threadsafe to schedule the coroutine onto this instance's event loop.
            # This ensures it runs safely even if the event is triggered immediately after loop setup
            # or from a different thread context (e.g., Zeroconf's internal threads).
            if self._loop and not self._loop.is_closed(): # Ensure loop is available and not closed
                # Schedule a coroutine as a task on the event loop
                self._loop.call_soon_threadsafe(
                    lambda: asyncio.ensure_future(
                        self._async_request_service_info(zeroconf, service_type, name),
                        loop=self._loop
                    )
                )
                logger.debug(f"Scheduled async request for service info for {name} using call_soon_threadsafe.")
            else:
                logger.error(f"Cannot schedule _async_request_service_info for {name}: event loop is not available or closed.")

        elif state_change == ServiceStateChange.Removed:
            # Remove peer from list if service is removed
            try:
                instance_name_part = name.split(SERVICE_TYPE)[0].strip('.')
                name_parts = instance_name_part.split('-')
                removed_device_id = '-'.join(name_parts[:-2])
                removed_port = int(name_parts[-2]) # Ensure correct parsing of port

                # Check if the peer to be removed actually exists and matches port
                if removed_device_id in self.peers and self.peers[removed_device_id][1] == removed_port:
                    del self.peers[removed_device_id]
                    logger.info(f"Removed peer {removed_device_id} (port {removed_port}) due to service removal. Current peers: {self.peers}")
                else:
                    logger.debug(f"Removed service {name} did not match an active peer or was an older instance (device_id: {removed_device_id}, port: {removed_port}).")
            except Exception as e:
                logger.warning(f"Could not parse removed service name {name}: {e}")

    async def _async_request_service_info(self, zeroconf: Zeroconf, service_type: str, name: str):
        """Asynchronously requests and processes service information."""
        logger.info(f"Requesting service info for: {name}")
        try:
            info = await zeroconf.async_get_service_info(service_type, name)
            if info:
                addresses = [
                    socket.inet_ntoa(addr) for addr in info.addresses
                ]
                port = info.port
                
                # Extract device_id from the instance name (e.g., "deviceA-5000-timestamp")
                # Assumes the instance name format is "device_id-port-timestamp"
                try:
                    name_parts = name.split(SERVICE_TYPE)[0].split('-')
                    discovered_device_id = '-'.join(name_parts[:-2])
                    discovered_port = int(name_parts[-2])
                    # Ensure the timestamp is parsed correctly by stripping any trailing dot
                    # This handles cases like '12345.'
                    discovered_timestamp = int(name_parts[-1].strip('.'))
                except Exception as e:
                    logger.warning(f"Could not parse device_id or port from service name {name}: {e}. Skipping processing.")
                    return # Skip this service if name format is unexpected

                # Ignore self-instance if discovered (crucial to avoid adding self as a peer)
                if discovered_device_id == self.device_id and discovered_port == self.port:
                    logger.debug(f"Ignoring self instance: {discovered_device_id}-{discovered_port} (Matches self's device_id and port).")
                    return

                # Choose the first available address (assuming IPv4 for simplicity)
                if addresses:
                    ip = addresses[0]
                    peer_key = discovered_device_id 
                    
                    # For simplicity, if a peer with this device_id already exists,
                    # we will overwrite it with the newly discovered info.
                    if peer_key in self.peers:
                        logger.debug(f"Overwriting existing peer data for {peer_key}. Old: {self.peers[peer_key]}, New: ({ip}, {port})")

                    self.peers[peer_key] = (ip, port)
                    logger.info(f"Found new peer: {discovered_device_id} at {ip}:{port} (instance: {name.split(SERVICE_TYPE)[0]}). Added to peers list.")
                    logger.debug(f"Current peers dict: {self.peers}")
                else:
                    logger.warning(f"No valid IP addresses found for service {name}.")
            else:
                logger.warning(f"No service info returned for {name}.")
        except asyncio.TimeoutError:
            logger.warning(f"Timeout while requesting service info for {name}. Peer might be unresponsive or network slow.")
        except Exception as e:
            logger.error(f"Error processing service info for {name}: {e}", exc_info=True)


    def run(self):
        """Starts the Zeroconf discovery service. This method blocks until unregister is called."""
        if self._is_running:
            logger.warning("Discovery service is already running.")
            return

        self._is_running = True
        # Create a new event loop for this thread to manage Zeroconf's async operations
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop) 

        # Initialize Zeroconf without the 'loop' argument as it's not universally supported in this version
        self.zeroconf_instance = Zeroconf()
        
        local_ip = self._get_local_ip()
        logger.info(f"Using interface {local_ip} for Zeroconf.")

        # Register self as a service
        properties = {"device_id": self.device_id.encode('utf-8')} # Encode properties to bytes
        self.service_info = ServiceInfo(
            SERVICE_TYPE,
            name=f"{self.instance_name}.{SERVICE_TYPE}", # Full service name
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=properties, 
            # ttl=TTL_SECONDS # Removed 'ttl' argument as it's not universally supported
        )
        logger.info(f"Registering service: {self.service_info.name} on {local_ip}:{self.port}")
        self.zeroconf_instance.register_service(self.service_info)
        logger.info(f"Service registered successfully: {self.service_info.name}")

        # Start browsing for other services immediately.
        # The `call_soon_threadsafe` in _on_service_state_change will handle scheduling
        # the info requests safely onto this loop.
        self.browser = ServiceBrowser(self.zeroconf_instance, SERVICE_TYPE, handlers=[self._on_service_state_change])
        logger.info("Starting to browse for services of type: %s", SERVICE_TYPE)
        
        # Now, run the asyncio event loop indefinitely
        try:
            self._loop.run_forever()
        except KeyboardInterrupt:
            logger.info("Discovery loop interrupted by KeyboardInterrupt.")
        except Exception as e:
            logger.error(f"Error in discovery event loop: {e}", exc_info=True)
        finally:
            logger.info(f"Discovery loop for {self.device_id} is stopping.")
            # Ensure unregistration is called when the loop stops
            self.unregister() 


    def unregister(self):
        """Unregisters services and closes Zeroconf instance."""
        if not self._is_running:
            logger.info("Discovery service not running, no need to unregister.")
            return

        logger.info(f"Attempting to unregister services and close zeroconf for {self.device_id}.")
        try:
            # Call the synchronous close method on the Zeroconf instance.
            # This method in older versions typically handles unregistering services
            # and stopping the browser automatically.
            if self.zeroconf_instance:
                self.zeroconf_instance.close()
                logger.info("Zeroconf instance closed.")
            
            # Attempt to stop and close the asyncio loop.
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(self._loop.stop)
            elif self._loop and not self._loop.is_closed():
                # If the loop is not running but not closed, close it.
                self._loop.close()
                logger.info("Asyncio loop closed.")


        except Exception as e:
            logger.error(f"Error unregistering Zeroconf services for {self.device_id}: {e}", exc_info=True)
        finally:
            self._is_running = False
            self.browser = None
            self.service_info = None
            self.zeroconf_instance = None
            self.peers = {} # Clear peers on shutdown
            if self._loop and self._loop.is_closed():
                self._loop = None


    def get_peers(self) -> Dict[str, Tuple[str, int]]:
        """Returns the currently discovered peers."""
        # Clean up peers that are no longer active (optional, Zeroconf handles this over time)
        # For a truly robust system, this might involve checking timestamps or last-seen times.
        return self.peers


# --- Test code for demonstration ---
def run_discovery_instance(port, device_id):
    """Function to run a PeerDiscovery instance in a separate thread."""
    discovery_instance = PeerDiscovery(port=port, device_id=device_id)
    # Store the instance so we can access its methods from the main thread if needed
    global_discovery_instances[device_id] = discovery_instance
    discovery_instance.run() # This call blocks the thread until unregister is called

def monitor_peers(discovery_instance: PeerDiscovery, interval: int = 5):
    """Monitors and prints the peers discovered by an instance."""
    while True:
        if not discovery_instance._is_running:
            logger.info(f"Monitor for {discovery_instance.device_id} stopping as discovery is not running.")
            break
        peers = discovery_instance.get_peers()
        if peers:
            logger.info(f"[{discovery_instance.device_id}] Discovered peers: {peers}")
        else:
            logger.info(f"[{discovery_instance.device_id}] No peers discovered yet.")
        time.sleep(interval)

# Global dictionary to hold discovery instances for managing them from main thread
global_discovery_instances: Dict[str, PeerDiscovery] = {}

if __name__ == "__main__":
    logger.info("Starting PeerDiscovery demonstration...")

    # Generate unique device IDs for our test instances
    device_id_1 = f"test-device-A-{str(uuid.uuid4())[:8]}"
    device_id_2 = f"test-device-B-{str(uuid.uuid4())[:8]}"

    port_1 = 5000
    port_2 = 5001

    # Create threads for each discovery instance
    # Each PeerDiscovery instance needs its own event loop, so running in separate threads is appropriate.
    thread_dev1 = threading.Thread(target=run_discovery_instance, args=(port_1, device_id_1), name=f"DiscoveryThread-{device_id_1}")
    thread_dev2 = threading.Thread(target=run_discovery_instance, args=(port_2, device_id_2), name=f"DiscoveryThread-{device_id_2}")

    # Start the discovery threads
    thread_dev1.start()
    thread_dev2.start()

    logger.info("Discovery instances started. Waiting for discovery...")

    try:
        # Give some time for discovery to happen and for threads to become fully ready
        print("\n--- Monitoring peers for 30 seconds (Press Ctrl+C to stop early) ---\n")
        
        # Give a small delay for the discovery instances' threads to start up.
        # This is separate from the asyncio loop's internal readiness.
        time.sleep(2) 

        # Start monitoring threads for each discovery instance
        monitor_thread_dev1 = threading.Thread(target=monitor_peers, args=(global_discovery_instances[device_id_1],), name=f"MonitorThread-{device_id_1}")
        monitor_thread_dev2 = threading.Thread(target=monitor_peers, args=(global_discovery_instances[device_id_2],), name=f"MonitorThread-{device_id_2}")
        
        monitor_thread_dev1.start()
        monitor_thread_dev2.start()

        # Keep the main thread alive for a duration or until interrupted
        time.sleep(30) # Run for 30 seconds

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Stopping discovery services...")
    finally:
        # Ensure unregister is called on both instances
        logger.info("Attempting to unregister both discovery instances...")
        if device_id_1 in global_discovery_instances:
            global_discovery_instances[device_id_1].unregister()
        if device_id_2 in global_discovery_instances:
            global_discovery_instances[device_id_2].unregister()

        # Wait for discovery threads to finish
        logger.info("Waiting for discovery threads to join...")
        thread_dev1.join(timeout=10)
        thread_dev2.join(timeout=10)

        # Wait for monitor threads to finish (they will stop once discovery is unregistered)
        logger.info("Waiting for monitor threads to join...")
        if monitor_thread_dev1.is_alive():
            logger.warning(f"Monitor thread {monitor_thread_dev1.name} is still alive. Joining.")
            monitor_thread_dev1.join(timeout=5)
        if monitor_thread_dev2.is_alive():
            logger.warning(f"Monitor thread {monitor_thread_dev2.name} is still alive. Joining.")
            monitor_thread_dev2.join(timeout=5)

        logger.info("PeerDiscovery demonstration finished.")
