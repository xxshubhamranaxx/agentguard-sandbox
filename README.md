# 🛡️ AgentGuard Sandbox — AI Prompt Injection & Guardrail Lab

An interactive AI Red-Teaming and LLM Security testing environment built to demonstrate prompt injection vulnerabilities and multi-layer defense-in-depth architectures.

🔗 **Live Demo:** https://agentguard-sandbox.vercel.app

## 🏗️ Defense Architecture (Hardened Mode)
- **Layer 1 — Input Heuristic Filter:** Regex-based pre-inference scanner detecting common jailbreak and system-override signatures.
- **Layer 2 — XML Delimiter Isolation:** Wraps untrusted user prompts inside `<user_input>` tags to prevent instruction-data confusion.
- **Layer 3 — Output DLP (Data Loss Prevention) Scanner:** Post-inference inspection ensuring sensitive credentials/flags are never leaked in responses.
