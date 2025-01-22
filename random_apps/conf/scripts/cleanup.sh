#!/bin/bash

# Cleanup

## Dirs
find . -type d -name "__py*" -exec rm -rf {} +
find . -type d -name "migr*" -exec rm -rf {} +
find . -type d -name "uploads" -exec rm -rf {} +

## Files
find . -type f -name "db.sqlite3" -exec rm -rf {} +
