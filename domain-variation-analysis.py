#!/usr/bin/env python3
"""
Updated Domain Analyzer

- Loads scoring weights from domain-variation-analysis-config.json
- Applies them in risk scoring
- If there's a tech TLD that's available and the base name exactly matches
  the original domain, assigns the highest score (default 100 from config).

Author: YourName
"""

import argparse
import sys
import re
import json
import whois
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
import jellyfish
import logging
from rich import print as rprint
from rich.logging import RichHandler
import socket
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("domain_analyzer")

# -------------- Load Config from JSON --------------
with open("domain-variation-analysis-config.json", "r") as f:
    config = json.load(f)

RISK_CATEGORIES = config["risk_categories"]
ATTACK_VECTOR_SCORES = config["attack_vector_scores"]
TLD_RISK_SCORES = config["tld_risk_scores"]
TECH_TLD_BONUS = config["tech_tld_bonus"]
EXACT_DOMAIN_MATCH_SCORE = config.get("exact_domain_match_score", 100)

# -------------- Example Keyboards and Patterns --------------
KEYBOARD_PROXIMITY = {
    'q': 'wa',
    'w': 'qeasd',
    'e': 'wrsdf',
    'r': 'etdfg',
    't': 'ryfgh',
    'y': 'tughj',
    'u': 'yihjk',
    'i': 'uojkl',
    'o': 'ipkl',
    'p': 'ol',
    'a': 'qwsz',
    's': 'awedxz',
    'd': 'serfcx',
    'f': 'drtgvc',
    'g': 'ftyhbv',
    'h': 'gyujnb',
    'j': 'huikmn',
    'k': 'jiolm',
    'l': 'kop',
    'z': 'asx',
    'x': 'zsdc',
    'c': 'xdfv',
    'v': 'cfgb',
    'b': 'vghn',
    'n': 'bhjm',
    'm': 'njk'
}

HOMOGRAPH_MAPPINGS = {
    'l': '1',
    'i': '1',
    'o': '0',
    's': '5',
    'a': '4',
    'e': '3',
    'b': '8',
    't': '7'
}

HOMOPHONES = {
    'to': ['two', 'too'],
    'for': ['four', '4'],
    'ate': ['eight', '8'],
    'eye': ['i'],
    'one': ['won', '1'],
    'two': ['to', 'too', '2'],
    'four': ['for', '4'],
    'eight': ['ate', '8'],
    'great': ['gr8'],
    'wait': ['w8'],
    'mate': ['m8'],
    'later': ['l8r'],
    'secure': ['secur'],
    'shop': ['shoppe'],
    'tech': ['tek'],
    'click': ['klik', 'clik'],
    'bank': ['banc', 'bancorp'],
    'pay': ['paye'],
    'mail': ['male'],
    'cash': ['kash', 'cache'],
    'quick': ['quik', 'qwik'],
    'smart': ['sm4rt'],
    'easy': ['ez', 'ezy'],
    'best': ['b3st'],
    'safe': ['sayf'],
    'care': ['kar'],
    'cloud': ['kl0ud'],
    'web': ['w3b'],
}

COMMON_TLDS = [
    'com', 'net', 'org', 'io', 'co', 'ai', 'app', 'dev', 'tech', 'cloud'
]

OMISSION_PATTERNS = {
    'double_letters': True,
    'silent_letters': {
        'h': ['wh', 'gh', 'ph'],
        'e': ['te', 'me', 'ne'],
        'w': ['wr', 'wh'],
        'k': ['kn'],
        'b': ['mb'],
        'n': ['mn'],
        't': ['st', 'ft']
    },
    'vowels': ['a', 'e', 'i', 'o', 'u'],
    'common_endings': ['ing', 'ed', 'er', 'or']
}

REPETITION_PATTERNS = {
    'double_chars': True,
    'vowels': ['a', 'e', 'i', 'o', 'u'],
    'common_doubles': ['l', 'm', 'n', 'r', 's', 't']
}


class DomainAnalyzer:
    def __init__(self, domain: str, risk_threshold: int = 0, check_availability: bool = False, debug: bool = False):
        self.domain = domain.lower()
        parts = self.domain.split('.')
        if len(parts) < 2:
            raise ValueError("Domain must include at least one dot (e.g., example.com)")
        self.base_name = '.'.join(parts[:-1])
        self.tld = parts[-1]
        self.risk_threshold = risk_threshold
        self.check_availability = check_availability
        self.debug = debug
        
        if self.debug:
            logger.setLevel(logging.DEBUG)
            logger.debug(f"Initialized analyzer for domain: {self.domain}")
            logger.debug(f"Base name: {self.base_name}")
            logger.debug(f"TLD: {self.tld}")

    def calculate_risk_score(self, variation: str, variation_type: str) -> int:
        if self.debug:
            logger.debug(f"\n[bold blue]Calculating risk score for: {variation}[/]")
            logger.debug(f"Attack vector: {variation_type}")

        score = 0

        # 1) Brand confusion (Jaro-Winkler)
        jw_sim = jellyfish.jaro_winkler_similarity(self.domain, variation)
        brand_confusion_score = int(40 * jw_sim)
        score += brand_confusion_score
        
        if self.debug:
            logger.debug(f"Jaro-Winkler similarity: {jw_sim:.3f}")
            logger.debug(f"Brand confusion score: {brand_confusion_score}")

        # 2) Attack vector weighting
        vector_score = ATTACK_VECTOR_SCORES.get(variation_type, ATTACK_VECTOR_SCORES['Other'])
        score += vector_score
        
        if self.debug:
            logger.debug(f"Attack vector score: {vector_score}")

        # 3) TLD risk
        var_tld = variation.split('.')[-1].lower()
        tld_risk = TLD_RISK_SCORES.get(var_tld, 3)
        score += tld_risk
        
        if self.debug:
            logger.debug(f"TLD risk score: {tld_risk}")

        # 4) Amplifiers
        amplifier_score = 0
        if re.search(r'\d', variation):
            amplifier_score += 5
            if self.debug:
                logger.debug("Added +5 for digit usage")
                
        hyphen_count = variation.count('-')
        if hyphen_count > 1:
            amplifier_score += 3
            if self.debug:
                logger.debug("Added +3 for multiple hyphens")
        elif hyphen_count == 1:
            amplifier_score += 1
            if self.debug:
                logger.debug("Added +1 for single hyphen")
                
        score += amplifier_score
        
        if self.debug:
            logger.debug(f"Total amplifier score: {amplifier_score}")
            logger.debug(f"[bold green]Final risk score: {min(score, 100)}[/]")

        return min(score, 100)

    def check_domain_status(self, domain: str) -> Dict:
        """Check if a domain is registered using WHOIS lookup with retries and better error handling."""
        if self.debug:
            logger.debug(f"\nChecking WHOIS for: {domain}")
            
        retries = 3
        delay = 1  # seconds between retries
        
        for attempt in range(retries):
            try:
                w = whois.whois(domain)
                
                # Check for common "not found" responses
                if w.status is None and w.registrar is None:
                    if self.debug:
                        logger.debug(f"Domain appears unregistered (no status/registrar)")
                    return {
                        'is_registered': False,
                        'expiration_date': None,
                        'registrar': None
                    }
                
                # Handle expiration date
                expiration_date = None
                if w.expiration_date:
                    if isinstance(w.expiration_date, list):
                        expiration_date = w.expiration_date[0]
                    else:
                        expiration_date = w.expiration_date
                
                if self.debug:
                    logger.debug(f"Domain is registered")
                    logger.debug(f"Registrar: {w.registrar}")
                    logger.debug(f"Expiration: {expiration_date}")
                
                return {
                    'is_registered': True,
                    'expiration_date': expiration_date.strftime('%Y-%m-%d') if expiration_date else None,
                    'registrar': w.registrar
                }
                
            except (whois.parser.PywhoisError, socket.error) as e:
                if "No match for domain" in str(e):
                    if self.debug:
                        logger.debug(f"Domain explicitly not found")
                    return {
                        'is_registered': False,
                        'expiration_date': None,
                        'registrar': None
                    }
                    
                if attempt < retries - 1:  # don't sleep on last attempt
                    if self.debug:
                        # Limit error message to first two lines
                        error_msg = str(e).split('\n')[:2]
                        logger.debug(f"WHOIS lookup failed (attempt {attempt + 1}/{retries}): {' '.join(error_msg)}")
                        logger.debug(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                    delay *= 2  # exponential backoff
                continue
                
            except Exception as e:
                if self.debug:
                    # Limit error message to first two lines
                    error_msg = str(e).split('\n')[:2]
                    logger.debug(f"Unexpected error during WHOIS lookup: {' '.join(error_msg)}")
                return {
                    'is_registered': None,  # Use None to indicate lookup failed
                    'expiration_date': None,
                    'registrar': None
                }
        
        if self.debug:
            logger.debug("All WHOIS lookup attempts failed")
        return {
            'is_registered': None,
            'expiration_date': None,
            'registrar': None
        }

    def generate_variations(self) -> List[Dict]:
        if self.debug:
            logger.debug("\n[bold]Starting variation generation[/]")
            
        variations = []
        
        # Character Omission
        if self.debug:
            logger.debug("\n[bold cyan]Generating Character Omission variations:[/]")
            
        for i in range(len(self.base_name)):
            new_name = self.base_name[:i] + self.base_name[i+1:]
            if self.debug:
                logger.debug(f"Omitted '{self.base_name[i]}' -> {new_name}")
            variations.append({
                'variation': f"{new_name}.{self.tld}",
                'type': 'Character Omission',
                'description': f"Removed '{self.base_name[i]}'"
            })

        # double letter omission
        for i in range(len(self.base_name) - 1):
            if self.base_name[i] == self.base_name[i + 1]:
                new_name = self.base_name[:i] + self.base_name[i + 1:]
                variations.append({
                    'variation': f"{new_name}.{self.tld}",
                    'type': 'Character Omission',
                    'description': f"Removed doubled letter '{self.base_name[i]}'"
                })

        # silent letter patterns
        for letter, patterns in OMISSION_PATTERNS['silent_letters'].items():
            for pattern in patterns:
                if pattern in self.base_name.lower():
                    new_name = self.base_name.replace(pattern, pattern.replace(letter, ''))
                    variations.append({
                        'variation': f"{new_name}.{self.tld}",
                        'type': 'Character Omission',
                        'description': f"Removed silent '{letter}' from '{pattern}'"
                    })

        # vowel omission in longer words
        words = re.findall(r'[a-z]+', self.base_name.lower())
        for word in words:
            if len(word) > 4:
                for vowel in OMISSION_PATTERNS['vowels']:
                    if vowel in word:
                        new_word = word.replace(vowel, '', 1)
                        new_name = self.base_name.replace(word, new_word)
                        variations.append({
                            'variation': f"{new_name}.{self.tld}",
                            'type': 'Character Omission',
                            'description': f"Removed vowel '{vowel}' from '{word}'"
                        })

        # common ending omissions
        for ending in OMISSION_PATTERNS['common_endings']:
            if self.base_name.lower().endswith(ending):
                new_name = self.base_name[:-len(ending)]
                variations.append({
                    'variation': f"{new_name}.{self.tld}",
                    'type': 'Character Omission',
                    'description': f"Removed ending '{ending}'"
                })

        # B: Keyboard Proximity
        for i, char in enumerate(self.base_name):
            if char in KEYBOARD_PROXIMITY:
                for nearby_char in KEYBOARD_PROXIMITY[char]:
                    new_name = self.base_name[:i] + nearby_char + self.base_name[i+1:]
                    variations.append({
                        'variation': f"{new_name}.{self.tld}",
                        'type': 'Keyboard Proximity',
                        'description': f"Mistyped '{char}' as '{nearby_char}'"
                    })

        # C: Homograph Attack
        for char, replacement in HOMOGRAPH_MAPPINGS.items():
            if char in self.base_name:
                new_name = self.base_name.replace(char, replacement)
                variations.append({
                    'variation': f"{new_name}.{self.tld}",
                    'type': 'Homograph Attack',
                    'description': f"Replaced '{char}' with '{replacement}'"
                })

        # D: TLD Variations
        for new_tld in COMMON_TLDS:
            if new_tld != self.tld:
                variations.append({
                    'variation': f"{self.base_name}.{new_tld}",
                    'type': 'TLD Variation',
                    'description': f"Changed TLD to .{new_tld}"
                })

        # E: Homophone Attacks
        for word in words:
            if word in HOMOPHONES:
                for homophone in HOMOPHONES[word]:
                    new_name = self.base_name.replace(word, homophone)
                    variations.append({
                        'variation': f"{new_name}.{self.tld}",
                        'type': 'Homophone Attack',
                        'description': f"Replaced '{word}' with sound-alike '{homophone}'"
                    })
            for dict_word, h_phones in HOMOPHONES.items():
                if dict_word in word and len(dict_word) > 2:
                    for homophone in h_phones:
                        new_name = self.base_name.replace(dict_word, homophone)
                        variations.append({
                            'variation': f"{new_name}.{self.tld}",
                            'type': 'Homophone Attack',
                            'description': f"Replaced '{dict_word}' with sound-alike '{homophone}'"
                        })

        # F: Character Repetition
        for i, char in enumerate(self.base_name):
            # simple doubling
            new_name = self.base_name[:i] + char + self.base_name[i:]
            variations.append({
                'variation': f"{new_name}.{self.tld}",
                'type': 'Character Repetition',
                'description': f"Doubled character '{char}'"
            })
        for letter in REPETITION_PATTERNS['common_doubles']:
            if letter in self.base_name:
                new_name = self.base_name.replace(letter, letter * 2)
                variations.append({
                    'variation': f"{new_name}.{self.tld}",
                    'type': 'Character Repetition',
                    'description': f"Doubled common letter '{letter}'"
                })
        for vowel in REPETITION_PATTERNS['vowels']:
            if vowel in self.base_name:
                new_name = self.base_name.replace(vowel, vowel * 2)
                variations.append({
                    'variation': f"{new_name}.{self.tld}",
                    'type': 'Character Repetition',
                    'description': f"Doubled vowel '{vowel}'"
                })
        # triple repetition
        for i, char in enumerate(self.base_name):
            if char in 'aeioulmnrs' and i > 0:
                new_name = self.base_name[:i] + char * 3 + self.base_name[i+1:]
                variations.append({
                    'variation': f"{new_name}.{self.tld}",
                    'type': 'Character Repetition',
                    'description': f"Tripled character '{char}'"
                })

        # ------------------------------------------------
        #  Score each variation & optionally check WHOIS
        # ------------------------------------------------
        scored_variations = []
        for v in variations:
            var_domain = v['variation'].lower()
            var_type = v['type']
            score = self.calculate_risk_score(var_domain, var_type)
            if score >= self.risk_threshold:
                v['risk_score'] = score
                scored_variations.append(v)

        if self.check_availability:
            if self.debug:
                logger.debug("\n[bold magenta]Checking domain availability:[/]")
                
            with ThreadPoolExecutor(max_workers=5) as executor:  # Reduced max_workers to avoid rate limiting
                future_to_var = {
                    executor.submit(self.check_domain_status, v['variation']): v
                    for v in scored_variations
                }
                for future in as_completed(future_to_var):
                    v = future_to_var[future]
                    status = future.result()
                    
                    if status['is_registered'] is None:
                        v['registered'] = "Unknown"
                        v['description'] += " [STATUS UNKNOWN]"
                        continue
                        
                    v['registered'] = status['is_registered']
                    v['expiration_date'] = status['expiration_date']
                    v['registrar'] = status['registrar']

                    var_tld = v['variation'].split('.')[-1].lower()
                    var_basename = '.'.join(v['variation'].split('.')[:-1])

                    if not status['is_registered']:
                        # +15 if attacker can buy it
                        v['risk_score'] = min(100, v['risk_score'] + 15)

                        # Extra tech TLD bonus
                        if var_tld in TECH_TLD_BONUS:
                            v['risk_score'] = min(100, v['risk_score'] + TECH_TLD_BONUS[var_tld])

                        # Exact domain match => highest score
                        # (i.e., same base_name as original + tech TLD + available)
                        if var_basename == self.base_name and var_tld in TECH_TLD_BONUS:
                            v['risk_score'] = EXACT_DOMAIN_MATCH_SCORE

                        v['description'] += " [AVAILABLE]"
                    else:
                        # +5 if it's registered
                        v['risk_score'] = min(100, v['risk_score'] + 5)
                        v['description'] += " [REGISTERED]"

                    if self.debug:
                        logger.debug(f"Domain {v['variation']}: {'Available' if not status['is_registered'] else 'Registered'}")
                        if status['is_registered']:
                            logger.debug(f"Registrar: {status['registrar']}")
                            logger.debug(f"Expires: {status['expiration_date']}")

        # Sort final
        scored_variations.sort(key=lambda x: x['risk_score'], reverse=True)
        return scored_variations


def get_risk_category(score: int) -> str:
    """Given a score, find which category it belongs to."""
    # Our config stores the categories as { "High": [60,79], ... }
    # Convert to integer ranges and check
    for category_name, rng in RISK_CATEGORIES.items():
        low, high = rng
        if low <= score <= high:
            return category_name
    return "Unknown"

def generate_markdown_table(variations: List[Dict]) -> str:
    headers = ['Domain Variation', 'Type', 'Risk Score', 'Risk Level', 'Status', 'Description']
    md = '| ' + ' | '.join(headers) + ' |\n'
    md += '|' + '|'.join(['---'] * len(headers)) + '|\n'
    
    for v in variations:
        status = "Unknown"
        if 'registered' in v:
            if v['registered'] == "Unknown":
                status = "Unknown"
            else:
                status = "Registered" if v['registered'] else "Available"
                # Only add expiration if domain is registered and has expiration date
                if v['registered'] and v.get('expiration_date'):
                    status += f" (Expires: {v['expiration_date']})"

        cat = get_risk_category(v['risk_score'])
        row = [
            v['variation'],
            v['type'],
            str(v['risk_score']),
            cat,
            status,
            v['description']
        ]
        md += '| ' + ' | '.join(row) + ' |\n'
    return md

def main():
    parser = argparse.ArgumentParser(
        description='Domain variation analyzer using external JSON config for weights/scoring.'
    )
    parser.add_argument('domain', help='Domain name to analyze (e.g., example.com)')
    parser.add_argument('-t', '--threshold', type=int, default=0,
                        help='Minimum risk score to include in results (0-100)')
    parser.add_argument('-o', '--output', choices=['markdown', 'csv', 'json'], default='markdown',
                        help='Output format (default: markdown)')
    parser.add_argument('--summary', action='store_true',
                        help='Include summary statistics in output')
    parser.add_argument('--check-availability', action='store_true',
                        help='Check domain registration status using WHOIS')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output showing scoring calculations')

    args = parser.parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    analyzer = DomainAnalyzer(
        args.domain, 
        args.threshold, 
        args.check_availability,
        debug=args.debug
    )
    variations = analyzer.generate_variations()
    df = pd.DataFrame(variations)

    if args.output == 'markdown':
        print("\n### Domain Variation Analysis (JSON-based weights)")
        print(f"\nAnalyzing variations for: {args.domain}")
        print("\nRisk Categories:")
        for cat, rng in RISK_CATEGORIES.items():
            low, high = rng
            subset = df[(df['risk_score'] >= low) & (df['risk_score'] <= high)]
            print(f" - {cat} ({low}–{high}): {len(subset)} variations")
        print("\nVariations by Risk Level:")
        print(generate_markdown_table(variations))

    elif args.output == 'csv':
        df['risk_level'] = df['risk_score'].apply(get_risk_category)
        print(df.to_csv(index=False))

    elif args.output == 'json':
        df['risk_level'] = df['risk_score'].apply(get_risk_category)
        print(df.to_json(orient='records', indent=2))

    if args.summary:
        print("\n### Summary Statistics")
        print(f"Total variations generated: {len(variations)}")

        # Group by type
        type_counts = df['type'].value_counts()
        print("\nVariations by Type:")
        for t, c in type_counts.items():
            pct = (c / len(variations)) * 100 if len(variations) else 0
            print(f" - {t}: {c} ({pct:.1f}%)")

        print("\nVariations by Risk Level:")
        for cat, rng in RISK_CATEGORIES.items():
            low, high = rng
            subset = df[(df['risk_score'] >= low) & (df['risk_score'] <= high)]
            if not subset.empty:
                pct = (len(subset) / len(variations)) * 100
                print(f" - {cat}: {len(subset)} ({pct:.1f}%)")
                if args.check_availability:
                    reg_subset = subset[subset.get('registered') == True]
                    print(f"   - Registered: {len(reg_subset)}")
                    print(f"   - Available: {len(subset) - len(reg_subset)}")


if __name__ == "__main__":
    main()
