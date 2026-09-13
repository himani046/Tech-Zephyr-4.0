from __future__ import annotations
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
from pathlib import Path
from .engine import AegisEngine

DATA=Path(__file__).resolve().parent.parent/'data'/'scenarios.json'
SCENARIOS=json.loads(DATA.read_text())['scenarios']
engine=AegisEngine(SCENARIOS)
app=FastAPI(title='AegisIAM API',version='1.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
class RunRequest(BaseModel): scenario_id:str='payment-role'
@app.get('/api/health')
def health(): return {'status':'ok','service':'AegisIAM'}
@app.get('/api/scenarios')
def scenarios(): return [{'id':s['id'],'name':s['name'],'description':s['description'],'role':s['role']} for s in SCENARIOS]
@app.get('/api/scenarios/{scenario_id}')
def scenario(scenario_id:str):
    s=engine.scenarios.get(scenario_id)
    if not s: raise HTTPException(404,'Scenario not found')
    return s
@app.post('/api/runs')
def create_run(req:RunRequest):
    if req.scenario_id not in engine.scenarios: raise HTTPException(404,'Scenario not found')
    return engine.run(req.scenario_id)
@app.get('/api/runs/{run_id}')
def get_run(run_id:str):
    r=engine.runs.get(run_id)
    if not r: raise HTTPException(404,'Run not found')
    return r
