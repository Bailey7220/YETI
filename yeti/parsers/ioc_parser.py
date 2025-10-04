#!/usr/bin/env python3
"""
YETI IOC Parser and Normalization Module
Extracts and normalizes Indicators of Compromise from threat intelligence feeds
Portfolio Project by Bailey Collins - Demonstrates IOC extraction and data normalization
"""

import re
import json
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from rich.console import Console
from rich.table import Table
from rich.progress import track
import logging

console = Console()
logger = logging.getLogger(__name__)

@dataclass
class IOC:
    """
    Structured representation of an Indicator of Compromise
    Demonstrates data modeling and professional code structure
    """
    value: str
    ioc_type: str  # ip, domain, url, hash, cve
    source_feed: str
    first_seen: str
    confidence: int  # 1-10 scale
    tags: List[str]
    context: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert IOC to dictionary for JSON serialization"""
        return asdict(self)
    
    def __hash__(self):
        """Make IOC hashable for deduplication"""
        return hash((self.value, self.ioc_type))

class IOCParser:
    """
    Professional IOC extraction and normalization engine
    Demonstrates pattern matching, data validation, and threat intelligence processing
    """
    
    def __init__(self):
        # Regex patterns for different IOC types
        self.patterns = {
            'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'),
            'url': re.compile(r'https?://[^\s/$.?#].[^\s]*'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,}'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        }
        
        # Common false positive patterns to exclude
        self.false_positives = {
            'ipv4': [
                r'^0\.0\.0\.0$',
                r'^127\.0\.0\.1$', 
                r'^255\.255\.255\.255$',
                r'^192\.168\.',
                r'^10\.',
                r'^172\.(1[6-9]|2[0-9]|3[01])\.'
            ],
            'domain': [
                r'^localhost$',
                r'\.local$',
                r'\.test$',
                r'example\.com$',
                r'\.internal$'
            ]
        }
        
        # Create output directories
        self.output_dir = Path("data/processed")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def is_false_positive(self, value: str, ioc_type: str) -> bool:
        """
        Check if extracted IOC is likely a false positive
        
        Args:
            value: The IOC value to check
            ioc_type: Type of IOC (ip, domain, etc.)
            
        Returns:
            True if likely false positive, False otherwise
        """
        if ioc_type in self.false_positives:
            for pattern in self.false_positives[ioc_type]:
                if re.search(pattern, value, re.IGNORECASE):
                    return True
        return False
    
    def extract_iocs_from_text(self, text: str, source_feed: str) -> List[IOC]:
        """
        Extract all IOCs from text content
        
        Args:
            text: Raw text content to parse
            source_feed: Name of the source feed
            
        Returns:
            List of extracted and validated IOCs
        """
        extracted_iocs = []
        timestamp = datetime.now().isoformat()
        
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            
            for match in matches:
                # Clean up the match
                clean_match = match.strip().lower() if ioc_type != 'cve' else match.upper()
                
                # Skip false positives
                if self.is_false_positive(clean_match, ioc_type):
                    continue
                
                # Determine confidence based on source and type
                confidence = self._calculate_confidence(ioc_type, source_feed)
                
                # Create IOC object
                ioc = IOC(
                    value=clean_match,
                    ioc_type=ioc_type,
                    source_feed=source_feed,
                    first_seen=timestamp,
                    confidence=confidence,
                    tags=self._generate_tags(ioc_type, source_feed),
                    context=f"Extracted from {source_feed}"
                )
                
                extracted_iocs.append(ioc)
        
        return extracted_iocs
    
    def _calculate_confidence(self, ioc_type: str, source_feed: str) -> int:
        """
        Calculate confidence score for an IOC based on type and source
        
        Args:
            ioc_type: Type of IOC
            source_feed: Source feed name
            
        Returns:
            Confidence score from 1-10
        """
        base_confidence = {
            'hash': 9,     # Hashes are very reliable
            'cve': 10,     # CVEs from CISA are definitive
            'ip': 7,       # IPs can be dynamic
            'domain': 8,   # Domains are fairly reliable
            'url': 6,      # URLs can change frequently
            'email': 5     # Emails can be spoofed
        }.get(ioc_type, 5)
        
        # Adjust based on source reputation
        source_modifiers = {
            'cisa_kev': 2,
            'feodo_tracker': 1,
            'malware_bazaar': 1,
            'emergingthreats': 1,
            'urlhaus': 0,
            'dan_tor': -1  # TOR exit nodes aren't necessarily malicious
        }
        
        modifier = source_modifiers.get(source_feed, 0)
        final_confidence = min(10, max(1, base_confidence + modifier))
        
        return final_confidence
    
    def _generate_tags(self, ioc_type: str, source_feed: str) -> List[str]:
        """
        Generate relevant tags for an IOC
        
        Args:
            ioc_type: Type of IOC
            source_feed: Source feed name
            
        Returns:
            List of descriptive tags
        """
        tags = [ioc_type, source_feed]
        
        # Add contextual tags based on source
        source_tags = {
            'feodo_tracker': ['banking_trojan', 'botnet'],
            'malware_bazaar': ['malware_sample'],
            'urlhaus': ['malicious_url'],
            'cisa_kev': ['known_exploited', 'vulnerability'],
            'emergingthreats': ['compromised_host'],
            'dan_tor': ['tor_exit_node', 'anonymization']
        }
        
        if source_feed in source_tags:
            tags.extend(source_tags[source_feed])
        
        return tags
    
    def parse_json_feed(self, filepath: str, source_feed: str) -> List[IOC]:
        """
        Parse JSON-formatted threat intelligence feeds (like CISA KEV)
        
        Args:
            filepath: Path to JSON file
            source_feed: Name of the source feed
            
        Returns:
            List of extracted IOCs
        """
        extracted_iocs = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            timestamp = datetime.now().isoformat()
            
            # Handle CISA KEV format specifically
            if source_feed == 'cisa_kev' and 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve_id = vuln.get('cveID', '')
                    if cve_id:
                        ioc = IOC(
                            value=cve_id,
                            ioc_type='cve',
                            source_feed=source_feed,
                            first_seen=timestamp,
                            confidence=10,
                            tags=['cve', 'known_exploited', 'cisa'],
                            context=f"CISA KEV: {vuln.get('shortDescription', 'No description')}"
                        )
                        extracted_iocs.append(ioc)
            
            logger.info(f"Parsed {len(extracted_iocs)} IOCs from JSON feed {source_feed}")
            
        except Exception as e:
            logger.error(f"Error parsing JSON feed {filepath}: {e}")
        
        return extracted_iocs
    
    def parse_text_feed(self, filepath: str, source_feed: str) -> List[IOC]:
        """
        Parse text-formatted threat intelligence feeds
        
        Args:
            filepath: Path to text file
            source_feed: Name of the source feed
            
        Returns:
            List of extracted IOCs
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            extracted_iocs = self.extract_iocs_from_text(content, source_feed)
            logger.info(f"Parsed {len(extracted_iocs)} IOCs from text feed {source_feed}")
            
            return extracted_iocs
            
        except Exception as e:
            logger.error(f"Error parsing text feed {filepath}: {e}")
            return []
    
    def deduplicate_iocs(self, iocs: List[IOC]) -> List[IOC]:
        """
        Remove duplicate IOCs while preserving the highest confidence version
        
        Args:
            iocs: List of IOCs to deduplicate
            
        Returns:
            Deduplicated list of IOCs
        """
        ioc_dict = {}
        
        for ioc in iocs:
            key = (ioc.value, ioc.ioc_type)
            
            if key not in ioc_dict or ioc.confidence > ioc_dict[key].confidence:
                ioc_dict[key] = ioc
        
        return list(ioc_dict.values())
    
    def save_iocs(self, iocs: List[IOC], filename: str) -> str:
        """
        Save parsed IOCs to multiple formats for different use cases
        
        Args:
            iocs: List of IOCs to save
            filename: Base filename (without extension)
            
        Returns:
            Path to main JSON output file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = self.output_dir / f"{filename}_{timestamp}"
        
        # Save as JSON (main format)
        json_path = f"{base_path}.json"
        with open(json_path, 'w') as f:
            json.dump([ioc.to_dict() for ioc in iocs], f, indent=2)
        
        # Save as CSV (for spreadsheet analysis)
        csv_path = f"{base_path}.csv"
        with open(csv_path, 'w', newline='') as f:
            if iocs:
                writer = csv.DictWriter(f, fieldnames=iocs[0].to_dict().keys())
                writer.writeheader()
                for ioc in iocs:
                    writer.writerow(ioc.to_dict())
        
        # Save as simple text list (for feeding to other tools)
        txt_path = f"{base_path}_values.txt"
        with open(txt_path, 'w') as f:
            for ioc in iocs:
                f.write(f"{ioc.value}\n")
        
        logger.info(f"Saved {len(iocs)} IOCs to {json_path}, {csv_path}, {txt_path}")
        return json_path
    
    def generate_summary_report(self, iocs: List[IOC]) -> Dict:
        """
        Generate summary statistics about parsed IOCs
        
        Args:
            iocs: List of IOCs to analyze
            
        Returns:
            Dictionary containing summary statistics
        """
        if not iocs:
            return {"total_iocs": 0, "message": "No IOCs found"}
        
        # Count by type
        type_counts = {}
        for ioc in iocs:
            type_counts[ioc.ioc_type] = type_counts.get(ioc.ioc_type, 0) + 1
        
        # Count by source
        source_counts = {}
        for ioc in iocs:
            source_counts[ioc.source_feed] = source_counts.get(ioc.source_feed, 0) + 1
        
        # Count by confidence level
        confidence_counts = {}
        for ioc in iocs:
            conf_range = f"{(ioc.confidence // 3) * 3 + 1}-{(ioc.confidence // 3 + 1) * 3}"
            confidence_counts[conf_range] = confidence_counts.get(conf_range, 0) + 1
        
        # Top tags
        all_tags = []
        for ioc in iocs:
            all_tags.extend(ioc.tags)
        
        tag_counts = {}
        for tag in all_tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        summary = {
            "total_iocs": len(iocs),
            "unique_iocs": len(set((ioc.value, ioc.ioc_type) for ioc in iocs)),
            "by_type": type_counts,
            "by_source": source_counts,
            "by_confidence": confidence_counts,
            "top_tags": dict(top_tags),
            "generated_at": datetime.now().isoformat()
        }
        
        return summary

def main():
    """
    Main function demonstrating IOC parsing capabilities
    """
    console.print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        YETI IOC Parser & Normalizer                         ║
║                     Threat Intelligence Data Processing                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """, style="bold cyan")
    
    parser = IOCParser()
    all_iocs = []
    
    # Find all downloaded feed files
    raw_dir = Path("data/raw")
    if not raw_dir.exists():
        console.print("❌ No raw data directory found. Run feed aggregation first.", style="red")
        return
    
    feed_files = list(raw_dir.glob("*"))
    if not feed_files:
        console.print("❌ No feed files found. Run feed aggregation first.", style="red")
        return
    
    console.print(f"📂 Found {len(feed_files)} feed files to parse", style="green")
    
    # Parse each feed file
    for filepath in track(feed_files, description="Parsing feeds..."):
        if filepath.suffix == '.json':
            # Extract source name from filename
            source_name = filepath.name.split('_')[0]
            iocs = parser.parse_json_feed(str(filepath), source_name)
        else:
            # Assume text format
            source_name = filepath.name.split('_')[0]
            iocs = parser.parse_text_feed(str(filepath), source_name)
        
        all_iocs.extend(iocs)
        console.print(f"   📋 {filepath.name}: {len(iocs)} IOCs extracted")
    
    # Deduplicate IOCs
    console.print(f"\n🔄 Deduplicating {len(all_iocs)} IOCs...")
    unique_iocs = parser.deduplicate_iocs(all_iocs)
    console.print(f"✅ {len(unique_iocs)} unique IOCs after deduplication")
    
    # Save results
    output_file = parser.save_iocs(unique_iocs, "parsed_iocs")
    console.print(f"💾 IOCs saved to: {output_file}")
    
    # Generate and display summary
    summary = parser.generate_summary_report(unique_iocs)
    
    # Create beautiful summary table
    table = Table(title="IOC Parsing Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    table.add_row("Total IOCs", str(summary["total_iocs"]))
    table.add_row("Unique IOCs", str(summary["unique_iocs"]))
    
    # Add type breakdown
    for ioc_type, count in summary["by_type"].items():
        table.add_row(f"  {ioc_type.upper()}", str(count))
    
    console.print(table)
    
    # Save summary
    summary_file = Path("data/processed") / f"parsing_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    console.print(f"\n📊 Summary report saved to: {summary_file}")
    console.print("\n🎯 Career Impact: This module demonstrates:", style="bold yellow")
    console.print("   • IOC extraction and normalization")
    console.print("   • Data validation and false positive filtering")
    console.print("   • Multiple output formats for different use cases") 
    console.print("   • Professional data modeling and statistics")
    console.print("   • Production-ready error handling")

if __name__ == "__main__":
    main()
