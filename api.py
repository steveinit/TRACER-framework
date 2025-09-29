#!/usr/bin/env python3
"""
FastAPI wrapper for TRACER Framework
Provides REST API endpoints for network path analysis
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import json
from datetime import datetime

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
    version="0.1.0"
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

# Pydantic models for request/response
class InitialDetection(BaseModel):
    threat_type: str
    source_ip: str
    destination_ip: str

class NetworkElement(BaseModel):
    element_type: str
    name: str
    movement_type: str = "direct"
    source_info: Optional[Dict[str, str]] = {}
    destination_info: Optional[Dict[str, str]] = {}

class CaseRequest(BaseModel):
    initial_detection: InitialDetection
    network_elements: Optional[List[NetworkElement]] = []

# Initialize storage backend with auto-detection
storage = create_storage()
print_storage_info()

@app.get("/")
async def root():
    """Health check endpoint"""
    storage_type = "MongoDB" if hasattr(storage, 'client') else "JSON"
    return {
        "message": "TRACER Framework API",
        "version": "0.1.0",
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
        "version": "0.1.0"
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
    """Get detailed information for a specific case"""
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
async def create_case(case_request: CaseRequest):
    """Create a new case with initial detection and optional network elements"""
    try:
        # Create analyzer instance
        analyzer = NetworkPathAnalyzer(storage)

        # Set initial detection
        analyzer.analysis["initial_detection"] = {
            "threat_type": case_request.initial_detection.threat_type,
            "source_ip": case_request.initial_detection.source_ip,
            "destination_ip": case_request.initial_detection.destination_ip
        }

        # Add network elements if provided
        for element in case_request.network_elements:
            element_data = {
                "type": element.element_type,
                "movement_type": element.movement_type,
                "source_info": element.source_info or {},
                "destination_info": element.destination_info or {}
            }

            analyzer.analysis["network_elements"][element.name] = element_data
            analyzer.analysis["path_sequence"].append(element.name)

        # Save case
        analyzer.save_case_to_db()

        return {
            "case_id": analyzer.case_id,
            "message": "Case created successfully",
            "case_data": analyzer.analysis
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/cases/{case_id}/elements")
async def add_network_element(case_id: str, element: NetworkElement):
    """Add a network element to an existing case"""
    try:
        if not storage.case_exists(case_id):
            raise HTTPException(status_code=404, detail="Case not found")

        # Load existing case
        analyzer = NetworkPathAnalyzer(storage)
        analyzer.load_existing_case(case_id)

        # Add new element
        element_data = {
            "type": element.element_type,
            "movement_type": element.movement_type,
            "source_info": element.source_info or {},
            "destination_info": element.destination_info or {}
        }

        analyzer.analysis["network_elements"][element.name] = element_data
        analyzer.analysis["path_sequence"].append(element.name)

        # Save updated case
        analyzer.save_case_to_db()

        return {
            "message": "Network element added successfully",
            "element_name": element.name,
            "case_data": analyzer.analysis
        }

    except HTTPException:
        raise
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