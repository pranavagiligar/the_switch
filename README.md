# **Scheduled Job Manager: Key Features**

This application provides a single, cohesive solution for persistent job scheduling, execution, and management, designed for administrators needing reliable automation.


## **Core Architecture**

|                       |                        |                                                                                     |
| --------------------- | ---------------------- | ----------------------------------------------------------------------------------- |
| **Component**         | **Technology**         | **Role**                                                                            |
| **Backend/Scheduler** | Go                     | Handles API, authentication, data persistence, and **CRON-based script execution**. |
| **Database**          | SQLite                 | Stores job definitions and user credentials persistently on disk (jobs.db).         |
| **Frontend**          | HTML, Tailwind CSS, JS | Single-page application (SPA) for real-time monitoring and management.              |


## **Feature Set**

### **1. Robust Scheduling & Execution**

- **Persistent CRON Scheduling:** Jobs are stored in the database and re-loaded automatically when the server starts, ensuring schedules survive restarts.

- **6-Field CRON Support:** Utilizes a cron parser that supports **second-level precision** (Seconds, Minutes, Hours, Day of Month, Month, Day of Week).

- **Shell Script Execution ("The Bot"):** Executes script content using /bin/bash -c, enabling the use of standard shell commands and local binaries (e.g., bash, python, node, etc.).

- **Execution Logging:** All scheduled attempts, successful executions, and failures (including script output) are logged directly to the Go server's console for easy monitoring.


### **2. Job Management & Control**

- **Full CRUD API:** Administrators can **C**reate, **R**ead, **U**pdate, and **D**elete job definitions via the web interface.

- **Real-time Scheduler Reload:** Any modification (create, update, delete) automatically triggers a **graceful stop and reload** of the internal CRON scheduler to apply changes instantly without requiring a full server restart.

- **Job Details:** Each job card displays its name, description, script content, creation time, CRON expression, and critical status indicators.


### **3. The Skip Count Mechanism**

The Skip Count feature provides temporary execution control without modifying the CRON schedule itself.

- **One-Click Skip:** The **Skip (Add 1)** action increments the job's SkipCount.

- **Effective Next Run Calculation:** The backend dynamically calculates the Next Run (Effective) time by advancing the schedule forward by the number of pending skips. This means the displayed time is the _true_ next time the script will run.

- **Job Lifecycle Integration:** When a scheduled time arrives, if SkipCount > 0, the job decrements the count and skips execution, maintaining the job's position in the CRON cycle.


### **4. Security and Usability**

- **JWT Authentication:** All API endpoints are protected by JWT tokens, requiring a successful username/password login.

- **Secure Password Storage:** The server uses **Bcrypt hashing** for storing user passwords in the database.

- **User Interface:** The interface is built with **Tailwind CSS** for a clean, responsive, and modern administrative experience.


## Example script
```bash
#!/bin/bash
osascript -e 'display dialog "Your script ran successfully" with title "Hello from Bash" giving up after 2'
```

## 6 field cron generator
- https://crontab.cronhub.io/
