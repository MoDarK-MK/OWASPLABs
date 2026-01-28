#!/usr/bin/env python3
"""
XSS Labs Launcher - Run all 20 XSS labs
Starts each lab on a different port (5001-5020)
"""

import subprocess
import os
import sys
import time
from pathlib import Path

# Lab directory
LABS_DIR = Path(__file__).parent

# Lab files
LABS = [
    ('lab_1_reflected_basic.py', 5001, 'Lab 1: Reflected XSS - Basic'),
    ('lab_2_stored_comments.py', 5002, 'Lab 2: Stored XSS - Comments'),
    ('lab_3_dom_innerhtml.py', 5003, 'Lab 3: DOM-based XSS'),
    ('lab_4_attribute_based.py', 5004, 'Lab 4: Attribute-based XSS'),
    ('lab_5_event_handler.py', 5005, 'Lab 5: Event Handler XSS'),
    ('lab_6_svg_based.py', 5006, 'Lab 6: SVG-based XSS'),
    ('lab_7_js_protocol.py', 5007, 'Lab 7: JavaScript Protocol Handler'),
    ('lab_8_css_based.py', 5008, 'Lab 8: CSS-based XSS'),
    ('lab_9_data_uri.py', 5009, 'Lab 9: Data URI XSS'),
    ('lab_10_json_response.py', 5010, 'Lab 10: JSON Response XSS'),
    ('lab_11_html5_data.py', 5011, 'Lab 11: HTML5 Data Attributes XSS'),
    ('lab_12_picture_tag.py', 5012, 'Lab 12: Picture/Source Tag XSS'),
    ('lab_13_filter_bypass_case.py', 5013, 'Lab 13: Filter Bypass - Case Variations'),
    ('lab_14_encoding_bypass.py', 5014, 'Lab 14: Filter Bypass - HTML Encoding'),
    ('lab_15_mutation_bypass.py', 5015, 'Lab 15: Filter Bypass - Mutation'),
    ('lab_16_js_context.py', 5016, 'Lab 16: Context-Aware XSS - JavaScript'),
    ('lab_17_url_context.py', 5017, 'Lab 17: Context-Aware XSS - URL'),
    ('lab_18_template_injection.py', 5018, 'Lab 18: Template Injection'),
    ('lab_19_polyglot.py', 5019, 'Lab 19: Polyglot XSS'),
    ('lab_20_waf_bypass.py', 5020, 'Lab 20: Advanced WAF Bypass'),
]

def launch_lab(lab_file, port, description):
    """Launch a single lab"""
    lab_path = LABS_DIR / lab_file
    
    if not lab_path.exists():
        print(f"❌ {description}: File not found {lab_path}")
        return None
    
    try:
        process = subprocess.Popen(
            [sys.executable, str(lab_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(LABS_DIR)
        )
        print(f"✓ {description} running on http://localhost:{port}")
        return process
    except Exception as e:
        print(f"❌ {description}: Failed to start - {e}")
        return None

def main():
    print("=" * 60)
    print("🛡️  XSS Labs Launcher - 20 Practical XSS Labs")
    print("=" * 60)
    print()
    
    processes = []
    
    print("Starting all XSS labs...")
    print("-" * 60)
    
    for lab_file, port, description in LABS:
        process = launch_lab(lab_file, port, description)
        if process:
            processes.append(process)
        time.sleep(0.5)  # Small delay between starts
    
    print("-" * 60)
    print(f"✓ Started {len(processes)}/{len(LABS)} labs")
    print()
    print("🌐 Access labs at:")
    print("-" * 60)
    
    for _, port, description in LABS:
        lab_num = description.split(':')[0].replace('Lab ', '')
        print(f"  Lab {lab_num.ljust(2)} → http://localhost:{port}")
    
    print("-" * 60)
    print()
    print("📝 Lab Guide:")
    print("  1. Open each lab URL in your browser")
    print("  2. Read the vulnerability description")
    print("  3. Follow the hints to craft an XSS payload")
    print("  4. Submit the flag when you successfully trigger XSS")
    print()
    print("🎯 Difficulty Levels:")
    print("  🟢 Beginner (Labs 1, 2, 4): Basic XSS concepts")
    print("  🟡 Intermediate (Labs 3, 5-12): DOM & advanced XSS")
    print("  🔴 Advanced (Labs 13-18): Filter bypass & context-aware")
    print("  ⚫ Master (Labs 19-20): Polyglot & WAF bypass")
    print()
    print("Press Ctrl+C to stop all labs")
    print()
    
    try:
        # Keep the script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        print("Stopping all labs...")
        for process in processes:
            if process:
                process.terminate()
        print("All labs stopped.")

if __name__ == '__main__':
    main()
