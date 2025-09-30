#!/usr/bin/env python3
"""
FastAPI wrapper for TRACER Framework
Provides REST API endpoints for network path analysis
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional, Union
import json
from datetime import datetime
from enum import Enum

from tracer import NetworkPathAnalyzer
from storage import create_storage, print_storage_info
import os

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, continue without it

app = FastAPI(
    title="TRACER Framework API",
    description="Network Path Analysis Tool REST API",
    version="0.2.0"
)

# Configure CORS origins from environment
cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enums for validation
class InvestigationStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ON_HOLD = "on_hold"
    ARCHIVED = "archived"

class MovementType(str, Enum):
    DIRECT = "direct"
    LATERAL = "lateral"
    PIVOT = "pivot"

# Pydantic models for request/response
class MinimalCaseRequest(BaseModel):
    """Minimal case creation - just the essentials for starting investigation"""
    threat_type: str = Field(..., description="Type of threat detected (e.g., 'SQL Injection', 'Malware C2')")
    source_ip: str = Field(..., description="Source IP address of the threat")
    destination_ip: str = Field(..., description="Destination IP address of the threat")
    description: Optional[str] = Field(None, description="Optional initial description or notes")
    investigator: Optional[str] = Field(None, description="Investigator name or ID")

class NetworkElement(BaseModel):
    """Network element to add to investigation path"""
    element_type: str = Field(..., description="Type of network element (firewall, switch, router, etc.)")
    name: str = Field(..., description="Name or identifier of the network element")
    movement_type: MovementType = Field(MovementType.DIRECT, description="How traffic moves through this element")
    source_info: Optional[Dict[str, str]] = Field(default_factory=dict, description="Source-side configuration details")
    destination_info: Optional[Dict[str, str]] = Field(default_factory=dict, description="Destination-side configuration details")
    notes: Optional[str] = Field(None, description="Additional notes about this element")

class CaseUpdateRequest(BaseModel):
    """Request model for PATCH operations on cases"""
    description: Optional[str] = None
    investigator: Optional[str] = None
    status: Optional[InvestigationStatus] = None
    network_elements: Optional[List[NetworkElement]] = None
    notes: Optional[str] = None


# Initialize storage backend with auto-detection
storage = create_storage()
print_storage_info()

@app.get("/")
async def root():
    """Health check endpoint"""
    storage_type = "MongoDB" if hasattr(storage, 'client') else "JSON"
    return {
        "message": "TRACER Framework API",
        "version": "0.2.0",
        "storage_backend": storage_type
    }

@app.get("/health")
async def health_check():
    """Detailed health check including storage status"""
    try:
        # Test storage connectivity
        cases = storage.list_cases()
        storage_status = "healthy"
        storage_type = "MongoDB" if hasattr(storage, 'client') else "JSON"
    except Exception as e:
        storage_status = f"error: {str(e)}"
        storage_type = "unknown"

    return {
        "status": "healthy" if storage_status == "healthy" else "degraded",
        "storage_backend": storage_type,
        "storage_status": storage_status,
        "version": "0.2.0"
    }

@app.get("/cases")
async def list_cases():
    """Get list of all existing cases"""
    try:
        cases = storage.list_cases()
        case_summaries = []

        for case_id in cases:
            case_data = storage.load_case(case_id)
            if case_data:
                summary = {
                    "case_id": case_id,
                    "timestamp": case_data.get("timestamp"),
                    "threat_type": case_data.get("initial_detection", {}).get("threat_type"),
                    "source_ip": case_data.get("initial_detection", {}).get("source_ip"),
                    "destination_ip": case_data.get("initial_detection", {}).get("destination_ip"),
                    "element_count": len(case_data.get("network_elements", {}))
                }
                case_summaries.append(summary)

        return {"cases": case_summaries}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    """Get detailed information for a specific case including investigation cursor"""
    try:
        if not storage.case_exists(case_id):
            raise HTTPException(status_code=404, detail="Case not found")

        case_data = storage.load_case(case_id)


        return {"case": case_data}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/cases")
async def create_case(case_request: MinimalCaseRequest):
    """Create a new case with minimal initial information for iterative investigation"""
    try:
        # Create analyzer instance
        analyzer = NetworkPathAnalyzer(storage)

        # Set initial detection with minimal required information
        analyzer.analysis["initial_detection"] = {
            "threat_type": case_request.threat_type,
            "source_ip": case_request.source_ip,
            "destination_ip": case_request.destination_ip
        }

        # Add optional fields
        if case_request.description:
            analyzer.analysis["description"] = case_request.description
        if case_request.investigator:
            analyzer.analysis["investigator"] = case_request.investigator

        # Initialize investigation status
        analyzer.analysis["status"] = InvestigationStatus.ACTIVE.value

        # Initialize empty collections for iterative building
        analyzer.analysis["notes"] = []

        # Save minimal case
        analyzer.save_case_to_db()

        return {
            "case_id": analyzer.case_id,
            "message": "Case created successfully - ready for iterative investigation",
            "status": analyzer.analysis["status"],
            "next_steps": [
                f"Use PATCH /cases/{analyzer.case_id} to add network elements",
                "Update investigation status as you progress",
                "Add notes and findings iteratively"
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/cases/{case_id}")
async def update_case(case_id: str, update_request: CaseUpdateRequest):
    """Update case with new information - supports iterative investigation workflow"""
    try:
        if not storage.case_exists(case_id):
            raise HTTPException(status_code=404, detail="Case not found")

        # Load existing case
        analyzer = NetworkPathAnalyzer(storage)
        analyzer.load_existing_case(case_id)

        updates_made = []

        # Update basic fields
        if update_request.description is not None:
            analyzer.analysis["description"] = update_request.description
            updates_made.append("description")

        if update_request.investigator is not None:
            analyzer.analysis["investigator"] = update_request.investigator
            updates_made.append("investigator")

        if update_request.status is not None:
            analyzer.analysis["status"] = update_request.status.value
            updates_made.append("status")

        # Add notes if provided
        if update_request.notes is not None:
            if "notes" not in analyzer.analysis:
                analyzer.analysis["notes"] = []
            analyzer.analysis["notes"].append({
                "timestamp": datetime.now().isoformat(),
                "content": update_request.notes
            })
            updates_made.append("notes")

        # Add network elements if provided
        if update_request.network_elements:
            elements_added = []
            for element in update_request.network_elements:
                element_data = {
                    "type": element.element_type,
                    "movement_type": element.movement_type.value,
                    "source_info": element.source_info,
                    "destination_info": element.destination_info,
                    "added_timestamp": datetime.now().isoformat()
                }

                if element.notes:
                    element_data["notes"] = element.notes

                analyzer.analysis["network_elements"][element.name] = element_data
                analyzer.analysis["path_sequence"].append(element.name)
                elements_added.append(element.name)

            updates_made.append(f"network_elements ({len(elements_added)} added)")


        # Save updated case
        analyzer.save_case_to_db()

        return {
            "message": f"Case updated successfully - {', '.join(updates_made)}",
            "case_id": case_id,
            "updates_made": updates_made,
            "total_elements": len(analyzer.analysis.get("path_sequence", []))
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/cases/{case_id}/elements")
async def add_network_element(case_id: str, element: NetworkElement):
    """Legacy endpoint - Add a single network element (use PATCH /cases/{case_id} instead)"""
    try:
        # Convert single element to update request format
        update_request = CaseUpdateRequest(network_elements=[element])
        return await update_case(case_id, update_request)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cases/{case_id}/report")
async def generate_case_report(case_id: str):
    """Generate a formatted report for a specific case"""
    try:
        if not storage.case_exists(case_id):
            raise HTTPException(status_code=404, detail="Case not found")

        # Load case and generate report
        analyzer = NetworkPathAnalyzer(storage)
        analyzer.load_existing_case(case_id)

        # Generate report data
        case_data = analyzer.analysis
        detection = case_data.get("initial_detection", {})
        elements = case_data.get("network_elements", {})
        sequence = case_data.get("path_sequence", [])

        # Count analysis metrics
        direct_count = sum(1 for name in sequence
                          if elements.get(name, {}).get("movement_type") == "direct")
        lateral_count = sum(1 for name in sequence
                           if elements.get(name, {}).get("movement_type") == "lateral")
        pivot_count = sum(1 for name in sequence
                         if elements.get(name, {}).get("movement_type") == "pivot")

        report = {
            "case_id": case_id,
            "threat_type": detection.get("threat_type"),
            "timestamp": case_data.get("timestamp"),
            "network_elements_analyzed": len(elements),
            "source_ip": detection.get("source_ip"),
            "destination_ip": detection.get("destination_ip"),
            "path_sequence": sequence,
            "network_elements": elements,
            "analysis_summary": {
                "direct_traversals": direct_count,
                "lateral_movements": lateral_count,
                "pivot_points": pivot_count
            }
        }

        return {"report": report}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/cases/{case_id}")
async def delete_case(case_id: str):
    """Delete a specific case"""
    try:
        if not storage.case_exists(case_id):
            raise HTTPException(status_code=404, detail="Case not found")

        # Note: JsonStorage doesn't have delete method, would need to implement
        # For now, return method not implemented
        raise HTTPException(status_code=501, detail="Delete functionality not yet implemented")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn

    # Get configuration from environment
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))
    log_level = os.getenv("LOG_LEVEL", "info").lower()

    uvicorn.run(app, host=host, port=port, log_level=log_level)