#!/usr/bin/env python3
"""
Trust → Recognize → ANALYZE → Communicate → Engage → Refine
TRACER-PAL (Path Analysis Tool)
Interactive tool for mapping network traffic from source to destination

Version 0.1 (Good Luck)
Author: Steve[InIT]
Author Note: I am a network security guy. I'm scrappy, but I'm not a developer.
What started as a neat little JSON tool I wrote and could understand
is now a Behemoth thanks to my co-writer
Claude Opus 4.1
Please, dear god, break it and submit feedback
https://github.com/steveinit/TRACER-framework.git
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
import os

# Import storage layer
from storage import StorageInterface, JsonStorage

class NetworkPathAnalyzer:
    def __init__(self, storage_backend: Optional[StorageInterface] = None):
        self.analysis = {
            "timestamp": datetime.now().isoformat(),
            "initial_detection": {},
            "enrichment_levels": [],
            "network_elements": {},
            "path_sequence": []  # Ordered list of elements in the path
        }

        # Setup storage backend (defaults to JSON for backward compatibility)
        self.storage = storage_backend or JsonStorage()

        # Setup real-time logging
        self.log_filename = f"tracer_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.case_id = f"CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Initialize storage
        self.storage.initialize_database()
        self.write_to_log("analysis_started", {"timestamp": self.analysis["timestamp"], "case_id": self.case_id})
    
    
    def display_current_path(self):
        """Display the current network path with insertion points"""
        print("\n" + "="*60)
        print("CURRENT NETWORK PATH")
        print("="*60)
        
        detection = self.analysis["initial_detection"]
        
        # Build path display with numbered insertion points
        path_display = []
        insertion_points = {}
        point_num = 1
        
        # Source
        path_display.append(f"SOURCE: {detection.get('source_ip', 'Unknown')}")
        insertion_points[point_num] = {"position": 0, "type": "after_source"}
        point_num += 1
        
        # Existing network elements in sequence
        for idx, element_name in enumerate(self.analysis.get("path_sequence", [])):
            element = self.analysis["network_elements"].get(element_name, {})
            movement = element.get("movement_type", "direct").replace("_", " ").title()
            
            path_display.append(f"  [{point_num-1}] <-- Insert Point")
            path_display.append(f"    ↓")
            path_display.append(f"  {element_name} ({element.get('type', 'unknown').upper()}) - {movement}")
            
            # Show any existing info for this element
            if element.get("source_info"):
                for info_type, info_value in element["source_info"].items():
                    path_display.append(f"      • {info_type}: {info_value}")
            
            insertion_points[point_num] = {"position": idx + 1, "type": "after_element", "element": element_name}
            point_num += 1
        
        # Final insertion point before destination
        path_display.append(f"  [{point_num-1}] <-- Insert Point")
        path_display.append(f"    ↓")
        
        # Destination
        path_display.append(f"DESTINATION: {detection.get('destination_ip', 'Unknown')}")
        
        # Print the path
        for line in path_display:
            print(line)
        
        return insertion_points
    
    def enrich_analysis(self):
        """Progressive enrichment of the network path with position selection"""
        enrichment_level = len(self.analysis.get("path_sequence", [])) + 1
        
        while True:
            print(f"\n--- ENRICHMENT LEVEL {enrichment_level} ---")
            
            # Display current path and get insertion points
            insertion_points = self.display_current_path()
            
            print("\nOptions:")
            print("  - Enter a number (1-{}) to add element at that position".format(len(insertion_points)))
            print("  - Type 'pivot' to add a lateral movement/pivot point")
            print("  - Type 'done' to finish enrichment")
            
            choice = input("\nYour choice: ").strip().lower()
            
            if choice == 'done':
                break
            elif choice == 'pivot':
                self.add_pivot_point()
                continue
            
            try:
                position = int(choice)
                if position not in insertion_points:
                    print(f"Invalid position. Please choose 1-{len(insertion_points)}")
                    continue
            except ValueError:
                print("Invalid input. Please enter a number, 'pivot', or 'done'")
                continue
            
            # Get network element information
            print("\n--- ADD NETWORK ELEMENT ---")
            element_type = input("Network element type (switch, router, firewall, NAC, etc.): ")
            element_name = input(f"{element_type.title()} name/identifier: ")
            
            # Ask about movement type
            movement_type = input("Is this direct traversal or lateral movement? (direct/lateral): ").lower()
            movement_type = "lateral_movement" if movement_type.startswith("lateral") else "direct_traversal"
            
            # Initialize element
            if element_name not in self.analysis["network_elements"]:
                self.analysis["network_elements"][element_name] = {
                    "type": element_type,
                    "source_info": {},
                    "destination_info": {},
                    "additional_data": [],
                    "movement_type": movement_type,
                    "path_position": position
                }
                
                # Insert into path sequence at the correct position
                insert_at = insertion_points[position]["position"]
                self.analysis["path_sequence"].insert(insert_at, element_name)
                
                # Log new network element
                log_data = {
                    "element_name": element_name,
                    "element_type": element_type,
                    "enrichment_level": enrichment_level,
                    "movement_type": movement_type,
                    "path_position": position,
                    "case_id": self.case_id
                }
                log_data.update(self.analysis["initial_detection"])
                self.write_to_log("network_element_added", log_data)
                self.save_case_to_db()
            
            # Get element information
            print(f"\n--- {element_name.upper()} INFORMATION ---")
            self.collect_element_info(element_name, "source")
            
            # Ask if user wants to add destination info
            if input("\nAdd destination-specific information for this element? (y/n): ").lower() == 'y':
                self.collect_element_info(element_name, "destination")
            
            enrichment_level += 1
    
    def add_pivot_point(self):
        """Add a pivot point for lateral movement in the attack"""
        print("\n--- ADD PIVOT POINT ---")
        print("A pivot point represents where the attacker moved laterally to a different system/network")
        
        pivot_name = input("Pivot point identifier (e.g., 'compromised_host_01'): ")
        pivot_ip = input("Pivot point IP address: ")
        pivot_type = input("Pivot type (e.g., RDP, SSH, SMB, PSExec): ")
        
        # Create a special pivot element
        pivot_element_name = f"PIVOT_{pivot_name}"
        
        self.analysis["network_elements"][pivot_element_name] = {
            "type": "pivot_point",
            "pivot_ip": pivot_ip,
            "pivot_method": pivot_type,
            "source_info": {"original_path": self.analysis["initial_detection"]["source_ip"]},
            "destination_info": {"pivot_target": pivot_ip},
            "movement_type": "lateral_movement"
        }
        
        # Display current path to choose where to insert the pivot
        insertion_points = self.display_current_path()
        position = input(f"\nWhere to insert this pivot point? (1-{len(insertion_points)}): ")
        
        try:
            pos = int(position)
            if pos in insertion_points:
                insert_at = insertion_points[pos]["position"]
                self.analysis["path_sequence"].insert(insert_at, pivot_element_name)
                print(f"Pivot point added at position {pos}")
        except ValueError:
            print("Invalid position, adding at end of path")
            self.analysis["path_sequence"].append(pivot_element_name)
    
    def load_existing_case(self, case_id: str):
        """Load existing case data from storage backend"""
        return self.storage.load_case(case_id)
    
    def collect_element_info(self, element_name: str, direction: str):
        """Collect information for source or destination on a network element"""
        element = self.analysis["network_elements"][element_name]
        
        while True:
            print(f"\nAdd {direction} information for {element_name} (or 'next' to continue):")
            print("Examples: MAC address, interface name, VLAN, ARP entry, CAM entry, etc.")
            
            info_type = input("Information type: ")
            if info_type.lower() == 'next':
                break
            
            info_value = input(f"{info_type}: ")
            
            # Store the information
            element[f"{direction}_info"][info_type] = info_value
            
            # Log and save to CSV
            csv_data = {
                "case_id": self.case_id,
                "element_name": element_name,
                "element_type": element["type"],
                "direction": direction,
                "info_type": info_type,
                "info_value": info_value,
                "movement_type": element.get("movement_type", "direct_traversal"),
                "path_position": element.get("path_position", 0)
            }
            csv_data.update(self.analysis["initial_detection"])
            
            self.write_to_log("information_added", csv_data)
            self.save_case_to_db()
    
    def save_case_to_db(self):
        """Save current case to storage backend"""
        case_data = {
            "case_id": self.case_id,
            "timestamp": self.analysis["timestamp"],
            "initial_detection": self.analysis["initial_detection"],
            "network_elements": self.analysis["network_elements"],
            "path_sequence": self.analysis["path_sequence"],
            "last_updated": datetime.now().isoformat()
        }
        self.storage.save_case(self.case_id, case_data)
    
    def write_to_log(self, action: str, data: Dict[str, Any]):
        """Write analysis actions to log file in real time"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "data": data
        }
        self.storage.write_log_entry(self.log_filename, log_entry)
    
    def check_existing_cases(self):
        """Check for existing cases in storage backend"""
        return self.storage.list_cases()
    
    def start_analysis(self):
        """Start the TRACER analysis with initial detection"""
        print("="*60)
        print("TRACER Framework - Network Path Analysis Tool")
        print("="*60)
        
        # Check for existing cases
        existing_cases = self.check_existing_cases()
        if existing_cases:
            print(f"\nFound {len(existing_cases)} existing case(s) in database:")
            for case in existing_cases[-5:]:  # Show last 5 cases
                print(f"  {case}")
            
            choice = input(f"\nContinue existing case, start new case, view case, or print case? (continue/new/view/print): ").lower()
            
            if choice == "continue":
                case_id = input("Enter case ID to continue: ")
                if case_id in existing_cases:
                    self.case_id = case_id
                    case_data = self.load_existing_case(case_id)
                    self.analysis.update(case_data)
                    print(f"\nLoaded existing case: {case_id}")
                    if self.analysis["initial_detection"]:
                        detection = self.analysis["initial_detection"]
                        print(f"Threat: {detection.get('threat_type', 'Unknown')}")
                        print(f"Source: {detection.get('source_ip', 'Unknown')}")
                        print(f"Destination: {detection.get('destination_ip', 'Unknown')}")
                        print(f"Network Elements: {len(self.analysis['network_elements'])}")
                        
                        # Continue with enrichment
                        self.enrich_analysis()
                        return True  # Analysis was performed
                else:
                    print("Case not found, starting new case...")
            elif choice == "view":
                case_id = input("Enter case ID to view: ")
                if case_id in existing_cases:
                    self.view_case(case_id)
                    return False  # Indicate no analysis was performed
            elif choice == "print":
                case_id = input("Enter case ID to print: ")
                if case_id in existing_cases:
                    self.print_case_to_file(case_id)
                    return False  # Indicate no analysis was performed
        
        # Get initial detection for new case
        print("\n--- INITIAL DETECTION ---")
        threat_type = input("Threat type detected (e.g., SQL Injection, Malware C2): ")
        source_ip = input("Source IP address: ")
        dest_ip = input("Destination IP address: ")
        
        self.analysis["initial_detection"] = {
            "threat_type": threat_type,
            "source_ip": source_ip,
            "destination_ip": dest_ip
        }
        
        # Log initial detection and save to JSON database
        log_data = dict(self.analysis["initial_detection"])
        log_data["case_id"] = self.case_id
        self.write_to_log("initial_detection", log_data)
        self.save_case_to_db()
        
        print(f"\nDetected: {threat_type}")
        print(f"  Source: {source_ip}")
        print(f"  Destination: {dest_ip}")
        
        # Start enrichment process
        self.enrich_analysis()
        return True  # Analysis was performed
    
    def view_case(self, case_id: str):
        """View existing case data with path visualization"""
        case_data = self.load_existing_case(case_id)
        
        print(f"\n--- CASE DETAILS: {case_id} ---")
        if case_data["initial_detection"]:
            detection = case_data["initial_detection"]
            print(f"Threat: {detection.get('threat_type', 'Unknown')}")
            print(f"Source: {detection.get('source_ip', 'Unknown')}")
            print(f"Destination: {detection.get('destination_ip', 'Unknown')}")
        
        # Display the path in sequence
        if case_data.get("path_sequence"):
            print("\n--- NETWORK PATH ---")
            print(f"SOURCE: {case_data['initial_detection'].get('source_ip', 'Unknown')}")
            
            for element_name in case_data["path_sequence"]:
                element = case_data["network_elements"].get(element_name, {})
                print(f"    ↓")
                movement = element.get("movement_type", "direct").replace("_", " ").title()
                
                if element.get("type") == "pivot_point":
                    print(f"  **PIVOT** {element_name}")
                    print(f"    Method: {element.get('pivot_method', 'Unknown')}")
                    print(f"    Target: {element.get('pivot_ip', 'Unknown')}")
                else:
                    print(f"  {element_name} ({element.get('type', 'unknown').upper()}) - {movement}")
                
                if element.get("source_info"):
                    print("    Source Info:")
                    for info_type, info_value in element["source_info"].items():
                        print(f"      • {info_type}: {info_value}")
                
                if element.get("destination_info"):
                    print("    Destination Info:")
                    for info_type, info_value in element["destination_info"].items():
                        print(f"      • {info_type}: {info_value}")
            
            print(f"    ↓")
            print(f"DESTINATION: {case_data['initial_detection'].get('destination_ip', 'Unknown')}")
        else:
            print("No network path recorded for this case.")

    def print_case_to_file(self, case_id: str):
        """Export case details to a text file with both human-readable and JSON formats"""
        case_data = self.load_existing_case(case_id)

        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"TRACER_Case_{case_id}_{timestamp}.txt"

        try:
            with open(filename, 'w') as f:
                # Header
                f.write("="*80 + "\n")
                f.write("TRACER FRAMEWORK - CASE EXPORT\n")
                f.write("="*80 + "\n")
                f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Case ID: {case_id}\n")
                f.write("="*80 + "\n\n")

                # Case details
                f.write(f"--- CASE DETAILS: {case_id} ---\n")
                if case_data["initial_detection"]:
                    detection = case_data["initial_detection"]
                    f.write(f"Threat: {detection.get('threat_type', 'Unknown')}\n")
                    f.write(f"Source: {detection.get('source_ip', 'Unknown')}\n")
                    f.write(f"Destination: {detection.get('destination_ip', 'Unknown')}\n")

                # Network path
                if case_data.get("path_sequence"):
                    f.write("\n--- NETWORK PATH ---\n")
                    f.write(f"SOURCE: {case_data['initial_detection'].get('source_ip', 'Unknown')}\n")

                    for element_name in case_data["path_sequence"]:
                        element = case_data["network_elements"].get(element_name, {})
                        f.write("    ↓\n")
                        movement = element.get("movement_type", "direct").replace("_", " ").title()

                        if element.get("type") == "pivot_point":
                            f.write(f"  **PIVOT** {element_name}\n")
                            f.write(f"    Method: {element.get('pivot_method', 'Unknown')}\n")
                            f.write(f"    Target: {element.get('pivot_ip', 'Unknown')}\n")
                        else:
                            f.write(f"  {element_name} ({element.get('type', 'unknown').upper()}) - {movement}\n")

                        if element.get("source_info"):
                            f.write("    Source Info:\n")
                            for info_type, info_value in element["source_info"].items():
                                f.write(f"      • {info_type}: {info_value}\n")

                        if element.get("destination_info"):
                            f.write("    Destination Info:\n")
                            for info_type, info_value in element["destination_info"].items():
                                f.write(f"      • {info_type}: {info_value}\n")

                    f.write("    ↓\n")
                    f.write(f"DESTINATION: {case_data['initial_detection'].get('destination_ip', 'Unknown')}\n")
                else:
                    f.write("\nNo network path recorded for this case.\n")

                # Analysis summary
                f.write("\n" + "="*80 + "\n")
                f.write("ANALYSIS SUMMARY\n")
                f.write("="*80 + "\n")

                if case_data.get("network_elements"):
                    direct_traversals = sum(1 for e in case_data["network_elements"].values()
                                           if e.get("movement_type") == "direct_traversal")
                    lateral_movements = sum(1 for e in case_data["network_elements"].values()
                                           if e.get("movement_type") == "lateral_movement")
                    pivot_points = sum(1 for e in case_data["network_elements"].values()
                                      if e.get("type") == "pivot_point")

                    f.write(f"Total Network Elements: {len(case_data['network_elements'])}\n")
                    f.write(f"Direct Traversals: {direct_traversals}\n")
                    f.write(f"Lateral Movements: {lateral_movements}\n")
                    f.write(f"Pivot Points: {pivot_points}\n")
                else:
                    f.write("No network elements recorded.\n")

                # Raw JSON data
                f.write("\n" + "="*80 + "\n")
                f.write("RAW CASE DATA (JSON)\n")
                f.write("="*80 + "\n")
                f.write("# This JSON data can be imported into other tools or used for analysis\n\n")

                # Load the complete case data from storage
                complete_case = self.storage.load_case(case_id)
                f.write(json.dumps(complete_case, indent=2))

                f.write("\n\n" + "="*80 + "\n")
                f.write("END OF CASE EXPORT\n")
                f.write("="*80 + "\n")

            print(f"\n✓ Case exported to: {filename}")
            print(f"  - Human-readable case details")
            print(f"  - Analysis summary with statistics")
            print(f"  - Complete JSON data for tool integration")

        except Exception as e:
            print(f"\n❌ Error exporting case: {e}")

    def generate_report(self):
        """Generate final TRACER analysis report with ordered path"""
        print("\n" + "="*60)
        print("TRACER ANALYSIS REPORT")
        print("="*60)
        
        detection = self.analysis["initial_detection"]
        print(f"\nCase ID: {self.case_id}")
        print(f"Threat Type: {detection['threat_type']}")
        print(f"Analysis Timestamp: {self.analysis['timestamp']}")
        print(f"Network Elements Analyzed: {len(self.analysis['network_elements'])}")
        
        # Display the complete path
        print(f"\n--- COMPLETE NETWORK PATH ---")
        print(f"SOURCE: {detection['source_ip']}")
        
        for element_name in self.analysis.get("path_sequence", []):
            element = self.analysis["network_elements"].get(element_name, {})
            print(f"    ↓")
            
            if element.get("type") == "pivot_point":
                print(f"  **LATERAL PIVOT**")
                print(f"    {element_name}")
                print(f"    Method: {element.get('pivot_method', 'Unknown')}")
                print(f"    Target: {element.get('pivot_ip', 'Unknown')}")
            else:
                movement = element.get("movement_type", "direct").replace("_", " ").title()
                print(f"  {element_name} ({element.get('type', 'unknown').upper()}) - {movement}")
            
            if element.get("source_info"):
                for info_type, info_value in element["source_info"].items():
                    print(f"      Source → {info_type}: {info_value}")
            
            if element.get("destination_info"):
                for info_type, info_value in element["destination_info"].items():
                    print(f"      Dest → {info_type}: {info_value}")
        
        print(f"    ↓")
        print(f"DESTINATION: {detection['destination_ip']}")
        
        # Analysis summary
        print("\n--- ANALYSIS SUMMARY ---")
        direct_traversals = sum(1 for e in self.analysis["network_elements"].values() 
                               if e.get("movement_type") == "direct_traversal")
        lateral_movements = sum(1 for e in self.analysis["network_elements"].values() 
                               if e.get("movement_type") == "lateral_movement")
        pivot_points = sum(1 for e in self.analysis["network_elements"].values() 
                          if e.get("type") == "pivot_point")
        
        print(f"Direct Traversals: {direct_traversals}")
        print(f"Lateral Movements: {lateral_movements}")
        print(f"Pivot Points: {pivot_points}")
        
        # Save options
        save = input("\nSave analysis to JSON file? (y/n): ")
        if save.lower() == 'y':
            filename = f"tracer_analysis_{self.case_id}.json"
            with open(filename, 'w') as f:
                json.dump(self.analysis, f, indent=2)
            print(f"Analysis saved to {filename}")
        
        print(f"Case data automatically saved to storage backend")
    
    def run(self):
        """Main execution method"""
        try:
            analysis_performed = self.start_analysis()

            # Only generate report if we actually performed analysis
            if analysis_performed:
                self.generate_report()

                print("\n" + "="*60)
                print("TRACER Analysis Complete")
                print("Trust → Recognize → Analyze → Communicate → Engage → Refine")
                print("="*60)

        except KeyboardInterrupt:
            print("\n\nAnalysis interrupted by user")
        except Exception as e:
            print(f"\nError during analysis: {e}")

def main():
    """Main entry point"""
    analyzer = NetworkPathAnalyzer()
    analyzer.run()

if __name__ == "__main__":
    main()
