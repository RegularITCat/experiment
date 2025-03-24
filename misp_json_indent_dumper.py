#!/usr/bin/env python3
import json
with open("misp_without_indent.json", "r") as f:
    data = json.load(f)
with open("misp_with_indent.json", "w") as f:
    json.dump(data, f, indent=3)
    
