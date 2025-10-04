#!/usr/bin/env python3
"""
YETI Feed Aggregation Module
Downloads and normalizes threat intelligence feeds from multiple sources
Portfolio Project by Bailey Collins - Demonstrates automated threat intel collection
"""

import requests
import json
import csv
import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.progress import track
from typing import Dict, List, Optional

# Initialize Rich console for beautiful output
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('yeti_feeds.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatFeedAggregator:
    """
    Professional threat intelligence feed aggregator
    Demonstrates enterprise-level threat intelligence collection capabilities
    """
    
    def __init__(self):
        self.feeds_config = {
            "feodo_tracker_ips": {
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "type": "ip_list",
                "description": "Feodo Tracker IP Blocklist - Banking Trojans",
                "format": "txt"
            },
            "malware_bazaar_hashes": {
                "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
                "type": "hash_list", 
                "description": "MalwareBazaar Recent SHA256 Hashes",
                "format": "txt"
            },
            "urlhaus_urls": {
                "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
                "type": "url_list",
                "description": "URLhaus Recent Malicious URLs",
                "format": "txt"
            },
            "cisa_kev": {
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "type": "cve_list",
                "description": "CISA Known Exploited Vulnerabilities",
                "format": "json"
            },
            "alienvault_reputation": {
                "url": "https://reputation.alienvault.com/reputation.data",
                "type": "ip_reputation",
                "description": "AlienVault IP Reputation Database",
                "format": "txt"
            },
            "emergingthreats_compromised": {
                "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                "type": "ip_list",
                "description": "Emerging Threats Compromised IPs",
                "format": "txt"
            },
            "dan_tor_exit": {
                "url": "https://www.dan.me.uk/torlist/",
                "type": "ip_list", 
                "description": "TOR Exit Node IP Addresses",
                "format": "txt"
            }
        }
        
        # Create data directories
        self.raw_dir = Path("data/raw")
        self.processed_dir = Path("data/processed")
        self.metadata_dir = Path("data/metadata")
        
        for directory in [self.raw_dir, self.processed_dir, self.metadata_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def download_feed(self, feed_name: str, feed_config: Dict) -> Optional[str]:
        """
        Download individual threat intelligence feed
        
        Args:
            feed_name: Name of the feed
            feed_config: Configuration dictionary for the feed
            
        Returns:
            Path to downloaded file or None if failed
        """
        try:
            console.print(f"🔽 Downloading {feed_name}...", style="blue")
            
            headers = {
                'User-Agent': 'YETI-ThreatIntel/1.0 (Educational/Portfolio Project)',
                'Accept': 'text/plain, application/json'
            }
            
            response = requests.get(
                feed_config["url"], 
                headers=headers,
                timeout=30,
                verify=True
            )
            response.raise_for_status()
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{feed_name}_{timestamp}.{feed_config['format']}"
            filepath = self.raw_dir / filename
            
            # Save raw data
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            # Create metadata
            metadata = {
                "feed_name": feed_name,
                "description": feed_config["description"],
                "download_time": datetime.now().isoformat(),
                "url": feed_config["url"],
                "file_size": len(response.content),
                "content_type": response.headers.get('content-type', 'unknown'),
                "status": "success"
            }
            
            metadata_file = self.metadata_dir / f"{feed_name}_{timestamp}_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Successfully downloaded {feed_name}: {len(response.content)} bytes")
            console.print(f"✅ {feed_name} downloaded successfully", style="green")
            
            return str(filepath)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download {feed_name}: {e}")
            console.print(f"❌ Failed to download {feed_name}: {e}", style="red")
            return None
        except Exception as e:
            logger.error(f"Unexpected error downloading {feed_name}: {e}")
            console.print(f"❌ Unexpected error: {e}", style="red")
            return None
    
    def download_all_feeds(self) -> Dict[str, str]:
        """
        Download all configured threat intelligence feeds
        
        Returns:
            Dictionary mapping feed names to downloaded file paths
        """
        console.print("🚀 Starting YETI Threat Intelligence Feed Collection", style="bold cyan")
        console.print(f"📁 Raw data directory: {self.raw_dir.absolute()}", style="yellow")
        
        downloaded_feeds = {}
        
        for feed_name, feed_config in track(
            self.feeds_config.items(), 
            description="Downloading feeds..."
        ):
            filepath = self.download_feed(feed_name, feed_config)
            if filepath:
                downloaded_feeds[feed_name] = filepath
        
        console.print(f"\n📊 Feed Collection Summary:", style="bold")
        console.print(f"   Total feeds configured: {len(self.feeds_config)}")
        console.print(f"   Successfully downloaded: {len(downloaded_feeds)}")
        console.print(f"   Failed downloads: {len(self.feeds_config) - len(downloaded_feeds)}")
        
        return downloaded_feeds
    
    def get_feed_statistics(self) -> Dict:
        """
        Generate statistics about downloaded feeds for reporting
        """
        stats = {
            "total_feeds": len(self.feeds_config),
            "last_update": datetime.now().isoformat(),
            "feed_details": []
        }
        
        for feed_name, config in self.feeds_config.items():
            # Find latest file for this feed
            pattern = f"{feed_name}_*"
            files = list(self.raw_dir.glob(pattern))
            
            if files:
                latest_file = max(files, key=lambda x: x.stat().st_mtime)
                file_size = latest_file.stat().st_size
                
                feed_stat = {
                    "name": feed_name,
                    "description": config["description"],
                    "type": config["type"],
                    "last_downloaded": datetime.fromtimestamp(latest_file.stat().st_mtime).isoformat(),
                    "file_size": file_size,
                    "status": "available"
                }
            else:
                feed_stat = {
                    "name": feed_name,
                    "description": config["description"],
                    "type": config["type"],
                    "status": "not_downloaded"
                }
            
            stats["feed_details"].append(feed_stat)
        
        return stats

def main():
    """
    Main execution function for feed aggregation
    Demonstrates professional CLI interface and error handling
    """
    console.print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    YETI - Your Everyday Threat Intelligence                  ║
║                          Feed Aggregation Module                             ║
║                                                                              ║
║  Portfolio Project: Automated Threat Intelligence Collection                ║
║  Author: Bailey Collins - Cybersecurity Professional                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """, style="bold cyan")
    
    try:
        # Initialize aggregator
        aggregator = ThreatFeedAggregator()
        
        # Download all feeds
        downloaded = aggregator.download_all_feeds()
        
        # Generate and save statistics
        stats = aggregator.get_feed_statistics()
        stats_file = Path("data/metadata/feed_statistics.json")
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        console.print(f"\n📈 Statistics saved to: {stats_file}", style="green")
        console.print("\n🎯 Career Impact: This module demonstrates:", style="bold yellow")
        console.print("   • Automated threat intelligence collection")
        console.print("   • Professional error handling and logging")
        console.print("   • Multiple threat feed integration")
        console.print("   • Metadata management and reporting")
        console.print("   • Production-ready code structure")
        
        return len(downloaded)
        
    except KeyboardInterrupt:
        console.print("\n⛔ Download interrupted by user", style="red")
        return 0
    except Exception as e:
        logger.error(f"Fatal error in main execution: {e}")
        console.print(f"\n💀 Fatal error: {e}", style="red")
        return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(0 if exit_code > 0 else 1)
