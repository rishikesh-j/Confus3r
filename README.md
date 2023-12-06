#  Confus3r - Dependency Confusion Checker.
<img src="gitimg/DALL-E.png" width="400"/>
Burp Extension to find dependency confusion attacks. 
 
Copyright (c) 2023 Rishikesh J


Credit to https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610 for the idea.

## Setup
For use with the professional version of Burp Suite. Ensure you have JPython loaded and setup
before installing.

## Usage

Once you've loaded the plugin there is some things to consider.
Burp performs threading on passive scanning by itself. This can be controlled by looking at the Scanner options.
The tool won't scan js,txt etc files but only JSON files to check for dependencies as to reduce the false positives.

