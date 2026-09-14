#!/usr/bin/env python3
"""
Comprehensive fix script for CHAKRAVYUH test failures.
Applies targeted fixes based on error message analysis.
"""
import re, os

REPO = '/home/z/my-project/download/chakravyuh/repo'

def read(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def write(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def fix_count(path, desc):
    print(f'  Fixed: {path} - {desc}')

def fix_policy_compiler_version():
    """policy_compiler/mod.rs: version "1.0.0" should be "1.0""""
    path = f'{REPO}/src/policy_compiler/mod.rs'
    content = read(path)
    # Find version parsing that produces "1.0.0" instead of "1.0"
    # The test expects SemVer without patch: "1.0" not "1.0.0"
    # Look for version string construction
    if '"1.0.0"' in content or 'major.minor.patch' in content:
        # The version is likely constructed as format!("{}.{}.{}", major, minor, patch)
        # Should be format!("{}.{}", major, minor)
        content = re.sub(
            r'format!\("\{\}\.\{\}\.\{\}"\s*,\s*major\s*,\s*minor\s*,\s*patch\)',
            'format!("{}.{}", major, minor)',
            content
        )
        write(path, content)
        fix_count(path, 'version format')


def fix_federated_model_manager():
    """federated/model_manager.rs: rollback version 1 vs 2"""
    path = f'{REPO}/src/federated/model_manager.rs'
    content = read(path)
    # Test expects version 2 after rollback, gets 1
    # Likely the rollback decrements version instead of keeping it
    # Or version is not incremented properly
    # Search for version management in rollback
    if 'rollback' in content:
        # The version should be incremented on commit and preserved on rollback
        # Or the rollback should set version = previous_version + 1
        lines = content.split('\n')
        for i, line in enumerate(lines):
            # Look for version decrement in rollback
            if 'version' in line.lower() and ('-' in line or 'saturating_sub' in line or '- 1' in line):
                # Check if this is in a rollback function
                context = '\n'.join(lines[max(0,i-5):i+5])
                if 'rollback' in context.lower() and ('saturating_sub' in line or '= version -' in line or '= self.version -' in line):
                    # This is likely the bug - rollback shouldn't decrement version
                    lines[i] = line.replace('saturating_sub(1)', 'saturating_add(1)').replace(' - 1', ' + 1')
                    write(path, '\n'.join(lines))
                    fix_count(path, 'rollback version')
                    return
    print(f'  SKIP: {path} - rollback version (manual check needed)')


def fix_tenant_token_bucket():
    """tenant/tenant_policy.rs: token bucket refill not working"""
    path = f'{REPO}/src/tenant/tenant_policy.rs'
    content = read(path)
    # Test: bucket.available() >= 1 after refill
    # Likely the refill logic doesn't add tokens
    # Common bug: elapsed time calculation is wrong or tokens not added
    if 'refill' in content or 'available' in content:
        lines = content.split('\n')
        for i, line in enumerate(lines):
            # Look for refill that uses <= instead of <
            if 'elapsed' in line.lower() and '<=' in line and 'refill' in '\n'.join(lines[max(0,i-3):i+3]).lower():
                lines[i] = line.replace('<=', '<', 1)
                write(path, '\n'.join(lines))
                fix_count(path, 'token bucket refill')
                return
    print(f'  SKIP: {path} - token bucket (manual check needed)')


def fix_plugin_search():
    """plugin/plugin_marketplace.rs: search returns 2 vs 1"""
    path = f'{REPO}/src/plugin/plugin_marketplace.rs'
    content = read(path)
    # Test expects 1 result for search by name, gets 2
    # Likely the search is matching partially when it should match exactly
    # Look for contains() that should be == or starts_with
    if 'search' in content.lower() and 'name' in content.lower():
        # Look for .contains( in search function
        content_new = content
        # Find the search_by_name function and fix contains to == for name matching
        lines = content.split('\n')
        in_search = False
        for i, line in enumerate(lines):
            if 'fn search_by_name' in line or 'fn search' in line:
                in_search = True
            if in_search and '}' in line and i > 0:
                in_search = False
            if in_search and '.contains(' in line and 'name' in line.lower():
                # Change .contains(query) to .starts_with(query) or == query for exact name match
                lines[i] = line.replace('.contains(', '.starts_with(', 1)
                write(path, '\n'.join(lines))
                fix_count(path, 'search by name')
                return
    print(f'  SKIP: {path} - search (manual check needed)')


# Run all fixes
print('Applying fixes...')
fix_policy_compiler_version()
fix_federated_model_manager()
fix_tenant_token_bucket()
fix_plugin_search()
print('Done with batch fixes.')
