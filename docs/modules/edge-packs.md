# ARC Edge Agent Packs — MKT-14

**Version:** v6.6  
**Tier:** Pro+ (Community Business+ via add-on)  
**Add-on:** `edge_agent_packs` — $15/mo

## Overview

ARC-like edge analytics packs that deploy as marketplace agents with the `edge_analytics` capability. Each pack declares its required sensor inputs, performs analysis, and returns a recommended action. Packs are registered via a `@register` class decorator and discoverable at runtime.

## Included Packs

### crop_health_monitor
Multispectral NDVI crop health analysis with stress detection.

**Required sensors:** `ndvi`, `red_edge`, `soil_moisture`

**Output:**
- `health_score` (0.0–1.0)
- `stress_level` (`none` / `moderate` / `severe`)
- `chlorophyll_index` (red_edge / ndvi ratio)

### yield_optimizer
Soil-weather yield optimization with irrigation scheduling (Penman–Monteith simplified).

**Required sensors:** `soil_moisture`, `temperature_c`, `humidity_pct`, `crop_type`

**Supported crop types:** `wheat`, `corn`, `soybean`, `cotton`, `rice`, `default`

**Output:**
- `evapotranspiration_mm`
- `moisture_deficit` / `moisture_surplus`
- `yield_risk` (0.0–1.0)
- `irrigation_schedule` (list of `{window, duration_h}`)

### disease_detector
AI-powered crop disease and pest detection.

**Required sensors:** `image_base64` (JPEG), `crop_type`  
**Optional:** `ndvi`, `location`

**Detection path:**
- With `ANTHROPIC_API_KEY`: Claude Vision (`claude-haiku-4-5-20251001`) analyzes field image
- Without API key: NDVI-based heuristic fallback

**Output:**
- `severity` (`none` / `low` / `moderate` / `high` / `severe`)
- `detected_issues` (list of disease/pest names)
- `area_affected_pct`
- `confidence` (0–100)
- `source` (`claude_vision` or `heuristic_ndvi`)

## Files

| File | Role |
|------|------|
| `warden/agents/__init__.py` | Package init |
| `warden/agents/packs/__init__.py` | Package init |
| `warden/agents/packs/base.py` | `EdgeAgentPack` ABC, `@register` decorator, `list_packs()`, `get_pack()` |
| `warden/agents/packs/crop_health_monitor.py` | `CropHealthMonitor` |
| `warden/agents/packs/yield_optimizer.py` | `YieldOptimizer` |
| `warden/agents/packs/disease_detector.py` | `DiseaseDetector` |
| `warden/agents/packs/api.py` | FastAPI router `/agents/packs/*` |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/agents/packs` | List all available packs with metadata |
| `POST` | `/agents/packs/{name}/deploy` | Register a pack as a marketplace agent |
| `POST` | `/agents/packs/{name}/analyze` | Run analysis pipeline on sensor data |

## Adding a Custom Pack

```python
from warden.agents.packs.base import EdgeAgentPack, register

@register
class MyCustomPack(EdgeAgentPack):
    name             = "my_custom_pack"
    description      = "Custom edge analytics pack."
    required_sensors = ["temp", "pressure"]
    version          = "1.0.0"

    async def analyze(self, sensor_data: dict) -> dict:
        return {"temp": sensor_data["temp"], "status": "ok"}

    async def recommend_action(self, analysis: dict) -> str:
        return "No action required."
```

Import the module at startup — the `@register` decorator adds it to the global registry automatically.

## Prometheus Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `warden_edge_pack_analyze_total` | `pack` | Analyze calls per pack name |
