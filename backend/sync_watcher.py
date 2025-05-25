# p2pshare/backend/sync_watcher.py

import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileDeletedEvent
import threading
import json
from backend.ws_sync import connected_peers
from shared.config import settings
from shared.logging_config import setup_logger

# Set up logger
logger = setup_logger(__name__)


class SyncEventHandler(FileSystemEventHandler):
    def __init__(self, share_dir: Path):
        self.share_dir = share_dir
        logger.info(f"Initialized sync event handler for directory: {share_dir}")

    def _broadcast(self, event_type: str, rel_path: str):
        message = json.dumps({
            "type": event_type,
            "path": rel_path,
            "origin": settings.device_id,
        })
        logger.debug(f"Broadcasting {event_type} event for {rel_path}")
        for device_id, ws in connected_peers.items():
            try:
                ws.send_text(message)
                logger.debug(f"Sent {event_type} event to {device_id}")
            except Exception as e:
                logger.error(f"Failed to send {event_type} event to {device_id}: {str(e)}", exc_info=True)

    def on_created(self, event):
        if not event.is_directory:
            rel_path = str(Path(event.src_path).relative_to(self.share_dir))
            logger.info(f"File created: {rel_path}")
            self._broadcast("created", rel_path)

    def on_modified(self, event):
        if not event.is_directory:
            rel_path = str(Path(event.src_path).relative_to(self.share_dir))
            logger.info(f"File modified: {rel_path}")
            self._broadcast("modified", rel_path)

    def on_deleted(self, event):
        if not event.is_directory:
            rel_path = str(Path(event.src_path).relative_to(self.share_dir))
            logger.info(f"File deleted: {rel_path}")
            self._broadcast("deleted", rel_path)


def start_sync_watcher():
    observer = Observer()
    event_handler = SyncEventHandler(settings.share_dir)
    observer.schedule(event_handler, path=str(settings.share_dir), recursive=True)
    observer.start()
    logger.info("File sync watcher started")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, stopping sync watcher")
        observer.stop()
    observer.join()


def run_in_thread():
    t = threading.Thread(target=start_sync_watcher, daemon=True)
    t.start()
    logger.info("Started sync watcher in background thread")
