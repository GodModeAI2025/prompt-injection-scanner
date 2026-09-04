"""Hooks, die den Scanner vor einen Agentenlauf haengen.

`pretooluse` ist ein PreToolUse-Hook fuer Claude Code: er liest den geplanten
Werkzeugaufruf, scannt jeden Text darin und blockiert, bevor das Werkzeug
laeuft.
"""
