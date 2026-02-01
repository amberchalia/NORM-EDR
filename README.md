# NORM-EDR

**NORM (Normal EDR)** is an experimental **kernel-mode EDR research project**
focused on **explainable detection** rather than silent blocking.

Instead of assigning scores or killing processes, NORM answers one question:

> **Why does this binary look suspicious?**

This project is built **step-by-step in public** as a learning and research journey
into how modern EDRs reason about behavior.

---

## 🎯 What NORM Currently Detects (v0.2)

### Process & Image Tracking (Kernel)
- Kernel-level process creation and termination tracking
- Kernel image load notifications (EXE + DLL)
- Accurate PID lifecycle correlation

### Static vs Dynamic DLL Analysis
- Static DLL imports via PE Import Table
- Runtime / dynamically loaded DLLs
- Detection of **undeclared DLL loads**
- Baseline suppression for common Windows DLLs

### Mode-Based Monitoring (New in v0.2)
NORM now supports **two execution modes**:

#### 🔹 Single-Binary Mode (default)
- Monitor **only one target binary**
- Ideal for:
  - Malware analysis
  - Red team payload inspection
  - Lab research
- Reduces noise and avoids “Christmas-tree” alerts

#### 🔹 Global Mode
- Monitor **all processes system-wide**
- Useful for:
  - Research
  - Signal exploration
  - Understanding system-wide behavior

Switching modes requires **changing a single enum value at compile time**.

---

## 🧠 What Makes NORM Different

- No scoring engine
- No silent blocking
- No opaque decisions

Instead, NORM produces **clear, human-readable kernel alerts** such as:



## 🔧 Build & Lab Setup

NORM is a kernel-mode driver and requires a dedicated lab environment.

A complete walkthrough covering:
- VM setup
- Test signing
- Driver compilation
- Driver loading

is available here:

📺 **How to Compile & Run NORM (Kernel Lab Setup)**  
👉 YouTube: https://www.youtube.com/watch?v=8NHgK_OSKj8

Written build steps are intentionally omitted to keep documentation
in sync with the video series.

## 📜 Disclaimer

This project is:
- For **learning**
- For **research**
- For **educational labs**

**Not production-ready.**
Do not deploy on real systems.

---

## ☕ Support

If you find this project useful and want to support continued development, 
you can help by buying me a coffee.

Your support helps cover:
- Lab infrastructure and VM crashes
- Kernel debugging time
- Writing documentation and blog posts
- Creating educational YouTube content

👉 [**Support me on Buy Me a Coffee**](https://buymeacoffee.com/amberchalia)


## Learn More
Read about my challenges and technical insights on my blog: [rootfu.in](https://rootfu.in).
