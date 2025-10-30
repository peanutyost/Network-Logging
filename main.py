"""Main application entry point."""
import logging
import signal
import sys
from packet_capture import PacketCapture
from dns_logger import DNSLogger
from traffic_monitor import TrafficMonitor
from config import config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Main network monitoring application."""
    
    def __init__(self):
        """Initialize the network monitor."""
        logger.info("Initializing network monitor...")
        
        # Initialize components
        self.dns_logger = DNSLogger()
        self.traffic_monitor = TrafficMonitor()
        
        # Initialize packet capture with callbacks
        self.packet_capture = PacketCapture(
            dns_callback=self.dns_logger.log_dns,
            traffic_callback=self.traffic_monitor.process_packet
        )
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.running = False
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self):
        """Start the network monitor."""
        logger.info("Starting network monitor...")
        logger.info(f"Capture config: {config.capture}")
        logger.info(f"Database config: {config.database.type}")
        
        self.running = True
        
        try:
            # Start packet capture
            self.packet_capture.start()
            
            # Keep main thread alive
            while self.running:
                import time
                time.sleep(1)
        
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the network monitor."""
        if not self.running:
            return
        
        logger.info("Stopping network monitor...")
        self.running = False
        
        # Stop packet capture
        if self.packet_capture:
            self.packet_capture.stop()
        
        # Flush traffic monitor cache
        if self.traffic_monitor:
            self.traffic_monitor.flush()
        
        # Close database connections
        if self.dns_logger:
            self.dns_logger.db.disconnect()
        
        logger.info("Network monitor stopped")


def main():
    """Main entry point."""
    monitor = NetworkMonitor()
    monitor.start()
    sys.exit(0)


if __name__ == "__main__":
    main()

