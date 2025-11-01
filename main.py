"""Main application entry point."""
import logging
import signal
import sys
import threading
import time
from typing import Optional
from datetime import datetime, timedelta
from packet_capture import PacketCapture
from dns_logger import DNSLogger
from traffic_monitor import TrafficMonitor
from threat_intel import ThreatIntelligenceManager
from database import get_database
from config import config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


class ThreatFeedScheduler:
    """Scheduler for updating threat intelligence feeds."""
    
    def __init__(self, threat_intel_manager: ThreatIntelligenceManager):
        """Initialize scheduler.
        
        Args:
            threat_intel_manager: Threat intelligence manager instance
        """
        self.threat_intel_manager = threat_intel_manager
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.update_interval_hours = 24  # Update feeds daily
    
    def start(self):
        """Start the scheduler."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("Threat feed scheduler started (daily updates)")
    
    def stop(self):
        """Stop the scheduler."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Threat feed scheduler stopped")
    
    def _run(self):
        """Main scheduler loop."""
        # Wait 30 seconds on startup before first update
        time.sleep(30)
        
        # Update all feeds immediately on startup
        self._update_all_feeds()
        
        # Then update daily
        while self.running:
            time.sleep(self.update_interval_hours * 3600)  # Wait 24 hours
            if self.running:
                self._update_all_feeds()
    
    def _update_all_feeds(self):
        """Update all enabled threat feeds."""
        logger.info("Updating all threat intelligence feeds...")
        for feed_name in self.threat_intel_manager.feeds.keys():
            try:
                logger.info(f"Updating threat feed: {feed_name}")
                result = self.threat_intel_manager.update_feed(feed_name)
                if result.get('success'):
                    logger.info(f"Successfully updated {feed_name}: {result.get('indicator_count', 0)} indicators")
                else:
                    logger.error(f"Failed to update {feed_name}: {result.get('error')}")
            except Exception as e:
                logger.error(f"Error updating feed {feed_name}: {e}", exc_info=True)


class NetworkMonitor:
    """Main network monitoring application."""
    
    def __init__(self):
        """Initialize the network monitor."""
        logger.info("Initializing network monitor...")
        
        # Initialize database and threat intelligence
        db = get_database()
        db.connect()
        db.create_tables()
        
        self.threat_intel_manager = ThreatIntelligenceManager(db)
        self.threat_scheduler = ThreatFeedScheduler(self.threat_intel_manager)
        
        # Initialize components
        self.dns_logger = DNSLogger(threat_intel_manager=self.threat_intel_manager)
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
            # Start threat feed scheduler
            self.threat_scheduler.start()
            
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
        
        # Stop threat scheduler
        if self.threat_scheduler:
            self.threat_scheduler.stop()
        
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

