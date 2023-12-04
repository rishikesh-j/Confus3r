#  Confus3r - Dependency Confusion Checker.
Burp Extension to find dependency confusion attacks. 
 
Copyright (c) 2023 Rishikesh J


Credit to https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610 for the idea.

## Setup
For use with the professional version of Burp Suite. Ensure you have JPython loaded and setup
before installing.

## Usage

Once you've loaded the plugin there is some things to consider.
Burp performs threading on passive scanning by itself. This can be controlled by looking at the Scanner options.
The tool only looks for package.json file,if burp has crawled over the file and if you navigated to the same you'll get an alert if any dependecy is missing.
