from __future__ import annotations
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
from pathlib import Path
from .engine import AegisEngine
from .import_analyzer import analyze_import

DATA=Path(__file__).resolve().parent.parent/'data'/'scenarios.json'
SCENARIOS=json.loads(DATA.read_text())['scenarios']
engine=AegisEngine(SCENARIOS)
app=FastAPI(title='AegisIAM API',version='1.1.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])

class RunRequest(BaseModel):
    scenario_id:str='payment-role'

@app.get('/api/health')
def health():
    return {'status':'ok','service':'AegisIAM'}

@app.get('/api/scenarios')
def scenarios():
    return [{'id':s['id'],'name':s['name'],'description':s['description'],'role':s['role']} for s in SCENARIOS]

@app.get('/api/scenarios/{scenario_id}')
def scenario(scenario_id:str):
    s=engine.scenarios.get(scenario_id)
    if not s: raise HTTPException(404,'Scenario not found')
    return s

@app.post('/api/runs')
def create_run(req:RunRequest):
    if req.scenario_id not in engine.scenarios: raise HTTPException(404,'Scenario not found')
    return engine.run(req.scenario_id)

@app.post('/api/analyze-upload')
async def analyze_upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith('.json'):
        raise HTTPException(400,'Please upload a .json IAM/RBAC export.')
    try:
        raw=await file.read()
        if len(raw)>5*1024*1024:
            raise HTTPException(413,'JSON file is too large. Maximum size is 5 MB.')
        data=json.loads(raw.decode('utf-8-sig'))
        return analyze_import(data,file.filename)
    except HTTPException:
        raise
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise HTTPException(400,f'Invalid JSON file: {exc}')
    except ValueError as exc:
        raise HTTPException(422,str(exc))
    except Exception as exc:
        raise HTTPException(500,f'Could not analyze the IAM export: {exc}')

@app.get('/api/runs/{run_id}')
def get_run(run_id:str):
    r=engine.runs.get(run_id)
    if not r: raise HTTPException(404,'Run not found')
    return r
