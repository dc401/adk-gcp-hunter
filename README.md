# adk-gcp-hunter
Multi-agentic threat hunting in GCP cloud logging with guard rails from finished threat intelligence PDF, Docx, and Txt files. Designed to accelerate hunting analysts automate and scale hunt sprints.

Core code developed by Dennis Chow and then enhanced by GenAI for significantly better graceful handling of edge cases and errors. Want to check it out live? Sign up for [Google NeXT '26 CUSTLT-116](https://www.googlecloudevents.com/next-vegas/session/3908778/build-an-ai-threat-hunter-agentic-workflows-with-google-adk)
![Google NeXT CUSTLT-116 Build an AI threat hunter in Google ADK by Dennis Chow](https://github.com/dc401/adk-gcp-hunter/blob/main/GoogleNeXT-2026-CUSTLT-116-placecard.PNG?raw=true)

## Notable Features

 - Automatable inputs and outputs using the CLI so you can call this solution as a tool to another agentic workflow. This does not out of the box use A2A or MCP for simplicity and less surface exposure.
 - Semantic chunking notable the number of files, or size with exponential back off to help with API quota usage with GCP Vertex 
 - Deterministic exception handling as guard rails in each tool to reduce the risk of common OWASP 10 and OWASP 10 LLM attacks.
 - Hybrid regex and LLM as a judge eval fallback hallucination detections using basic confidence scoring weighted for each claim. Low confidence scores only soft fail and warn the analyst at the end. Provides recommendations on where to look
 - Google Search grounding sanitization egress removes sensitive things like service account details, project id, and other resources, or IPv4 addresses from the searches should agents need to do research
 - Post report output JSON repair. ADK pydantic schemas will cause hard failures at the end and stop the workflow. Repairing imperfect JSON was then implemented as its own function after ADK completes for machine readability and reliability
 - Fallback reporting in the too many results are listed causing token spikes. Semantic truncation is also used and warned and then redirected to validate findings.
 - Hallucination on final report filters out possible issues ahead of time instead of failing 'inline' and crashing
 - Time aware look-back default  between 3, 7, and 14 days for arguments to be used with `gcloud` tooling
 - Custom session result states plugin in use to capture output logging no matter what mode is used `adk web` vs. `adk run`

## Disclaimer
There is no expressed warranty. GenAI does have failures, even with safeguards here. For now, use a hunting analyst to validate results each time.

## Release Notes
 - Current release: v1.5.0  Uses Google ADK for Python 1.23 pinned. The time of analysis is roughly 10-15 minutes. Deployment time to load the terraform sample TTPs from the cti_src aligned simulation is another 15-20 minutes on average.
	 - New Features
		 -  v1.5 Logging greatly enhanced for interactive (adk web) and non-interactive (adk run piped std in) to include hunting_results folder with raw gcloud tool output for evidence serving as a 'claims' validation for LLM as a judge hallucination detection. New tool added hallucination_detector that abstracts the original deterministic detections with more patterns and uses "soft fail" for scoring hallucination risk including regex on command execution vs. results after JSON report refinement
		 - v1.4.1 Non-interactive mode `adk run ./gcphunter_agent < <(echo "start hunt")` . Includes more refinement passes 
		 - v1.0 - MVP release deterministic guard rails and input validation without LLM as a Judge. Exponential backoff set aggressively for quota consumption reasons. Gemini 2.5 pro and flash are used
 - **Windows** users should uncheck the commented out item in requirements.txt when performing the venv activation
 
 ## Requirements
 
 - `gcloud` should be installed and configured on the system with the ***target*** project-id you wish to hunt in; ideally with a service account with oauth with read specific permissions.
 - `terraform` if you wish to deploy the sample TTP activity modules from gcp-threat-sim-tf that align to the most of the TTPs from the cti_src folder. 
 - `python3` should be installed to the latest stable version but this was tested on 3.11.x at the time of development on Windows and MacOS
 - Note: If you do not have the above, recommend trying this out in a GCP project sandbox not connected to an org, within cloudshell using your owner permissions.

 ## Google ADK General Flow
 ![Google ADK GCP Hunter Logical Flow](https://github.com/dc401/adk-gcp-hunter/blob/main/adk-highlevel-workflow.png?raw=true)

 ## Demo Video
 Click Play below for a 2 minute (4x speed demo. Total duration time ~10 minutes excluding terraform deploy and destroy)
[![Time Lapse Video of ADK GCP Hunter 1.5 Demo ](https://img.youtube.com/vi/Egh1JBJytm4/maxresdefault.jpg)](https://www.youtube.com/watch?v=Egh1JBJytm4))
