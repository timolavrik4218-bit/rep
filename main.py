import hashlib
import hmac
import os
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import Response
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("DB_LINK")
SUPABASE_KEY = os.getenv("DB_KEY")
cookie_secret = os.getenv("COOKIE_SECRET")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("DB_LINK і DB_KEY мають бути вказані у файлі .env")
if not cookie_secret:
    raise RuntimeError("COOKIE_SECRET має бути вказаний у файлі .env")
COOKIE_SECRET: str = cookie_secret

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

OWNER_COOKIE = "owner"
COOKIE_MAX_AGE = 30 * 24 * 60 * 60

app = FastAPI(redirect_slashes=False)

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


class Task(BaseModel):
    title: str


class TaskUpdate(BaseModel):
    title: Optional[str] = None


def get_owner_id(request: Request) -> tuple[str, bool]:
    cookie = request.cookies.get(OWNER_COOKIE, "")
    owner_id, separator, signature = cookie.partition(".")

    if separator:
        expected_signature = hmac.new(
            COOKIE_SECRET.encode(),
            owner_id.encode(),
            hashlib.sha256,
        ).hexdigest()
        try:
            is_valid_id = uuid.UUID(owner_id).hex == owner_id
        except ValueError:
            is_valid_id = False
        if is_valid_id and hmac.compare_digest(signature, expected_signature):
            return owner_id, False

    return uuid.uuid4().hex, True


def set_owner_cookie(response: Response, owner_id: str) -> None:
    signature = hmac.new(
        COOKIE_SECRET.encode(),
        owner_id.encode(),
        hashlib.sha256,
    ).hexdigest()
    response.set_cookie(
        key=OWNER_COOKIE,
        value=f"{owner_id}.{signature}",
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
    )


def get_all_tasks(owner_id: str):
    return (
        supabase.table("tasks")
        .select("*")
        .eq("owner_id", owner_id)
        .execute()
        .data
    )


@app.get("/")
@app.get("/show-tasks")
def tasksPage(request: Request):
    owner_id, is_new = get_owner_id(request)
    response = templates.TemplateResponse(
        request=request,
        name="tasks.html",
        context={"tasks": get_all_tasks(owner_id)}
    )
    if is_new:
        set_owner_cookie(response, owner_id)
    return response


@app.get("/check")
def getTasks(request: Request, response: Response):
    owner_id, is_new = get_owner_id(request)
    if is_new:
        set_owner_cookie(response, owner_id)
    return get_all_tasks(owner_id)


@app.post("/new")
def addTask(task: Task, request: Request, response: Response):
    owner_id, is_new = get_owner_id(request)
    title = task.title.strip()
    if not title:
        raise HTTPException(status_code=422, detail="Назва завдання не може бути порожньою")
    result = (
        supabase.table("tasks")
        .insert({"title": title, "owner_id": owner_id})
        .select()
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=500, detail="Завдання не збережено в Supabase")
    if is_new:
        set_owner_cookie(response, owner_id)
    return result.data[0]


@app.patch("/item-edit/{task_id}")
def editTask(task_id: int, task: TaskUpdate, request: Request, response: Response):
    owner_id, is_new = get_owner_id(request)
    updates = task.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="Немає змін для збереження")
    if "title" in updates:
        title = updates["title"]
        if title is None or not title.strip():
            raise HTTPException(status_code=422, detail="Назва завдання не може бути порожньою")
        updates["title"] = title.strip()

    result = (
        supabase.table("tasks")
        .update(updates)
        .eq("id", task_id)
        .eq("owner_id", owner_id)
        .select()
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Завдання не знайдено")
    if is_new:
        set_owner_cookie(response, owner_id)
    return result.data[0]


@app.delete("/item-delete/{task_id}")
def deleteTask(task_id: int, request: Request, response: Response):
    owner_id, is_new = get_owner_id(request)
    result = (
        supabase.table("tasks")
        .delete()
        .eq("id", task_id)
        .eq("owner_id", owner_id)
        .select()
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Завдання не знайдено")
    if is_new:
        set_owner_cookie(response, owner_id)
    return {"message": "success", "task": result.data[0]}
