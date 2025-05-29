# Threat Hunting - Suspected Data Exfiltration

For the sake of this lab, we assume the name of the device that John Doe primarily uses is **"zack-bruteforce."**

## 1. Preparation

**Goal:** Set up the hunt by defining what you're looking for.

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).

John is an administrator on his device and is not limited on which applications he uses. He may try to archive/compress sensitive information and send it to a private drive, etc.
