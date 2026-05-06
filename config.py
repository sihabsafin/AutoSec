import os

def _secret(key: str, default: str = "") -> str:
    try:
        import streamlit as st
        val = st.secrets.get(key, "")
        return val if val else os.getenv(key, default)
    except Exception:
        return os.getenv(key, default)

def get_llm(temperature: float = 0.2):
    from crewai import LLM
    groq_key   = _secret("GROQ_API_KEY")
    gemini_key = _secret("GEMINI_API_KEY")

    if groq_key:
        os.environ["GROQ_API_KEY"] = groq_key
    if gemini_key:
        os.environ["GEMINI_API_KEY"] = gemini_key

    if groq_key:
        try:
            return LLM(
                model="groq/llama-3.3-70b-versatile",
                api_key=groq_key,
                temperature=temperature
            )
        except Exception:
            pass

    if gemini_key:
        try:
            return LLM(
                model="gemini/gemini-2.0-flash",
                api_key=gemini_key,
                temperature=temperature
            )
        except Exception:
            pass

    raise ValueError(
        "No API key found. Add GROQ_API_KEY or GEMINI_API_KEY to .streamlit/secrets.toml"
    )

SUPABASE_URL = _secret("SUPABASE_URL")
SUPABASE_KEY = _secret("SUPABASE_KEY")