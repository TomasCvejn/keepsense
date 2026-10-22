from fastapi import FastAPI

from keepsense.routers import compare, health

app = FastAPI()
app.include_router(health.router)
app.include_router(compare.router)
