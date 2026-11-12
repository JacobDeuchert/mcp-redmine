import os, yaml, pathlib, json, uuid, threading
from urllib.parse import urljoin

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.logging import get_logger

### Constants ###

VERSION = "2026.01.13.152335"

# Load OpenAPI spec
current_dir = pathlib.Path(__file__).parent
with open(current_dir / 'redmine_openapi.yml') as f:
    SPEC = yaml.safe_load(f)

# Constants from environment
REDMINE_URL = os.environ['REDMINE_URL'].rstrip('/') + '/'  # Normalize to always end with /
REDMINE_API_KEY = os.environ['REDMINE_API_KEY']
REDMINE_RESPONSE_FORMAT = os.environ.get('REDMINE_RESPONSE_FORMAT', 'yaml').lower()

# Default project for curated tools (id or identifier). Empty means no default.
REDMINE_PROJECT = os.environ.get('REDMINE_PROJECT', '').strip()

# Custom headers (format: "Header1: Value1, Header2: Value2")
REDMINE_HEADERS = {}
if custom_headers := os.environ.get('REDMINE_HEADERS', ''):
    for header in custom_headers.split(','):
        if ':' in header:
            key, value = header.split(':', 1)
            REDMINE_HEADERS[key.strip()] = value.strip()

# Allowed directories for upload/download (secure by default - disabled if not set)
REDMINE_ALLOWED_DIRECTORIES = [
    pathlib.Path(d.strip()).resolve()
    for d in os.environ.get('REDMINE_ALLOWED_DIRECTORIES', '').split(',')
    if d.strip()
]

# SSL verification (disabled only when explicitly set to "1")
REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS = os.environ.get('REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS') == '1'

if "REDMINE_REQUEST_INSTRUCTIONS" in os.environ:
    with open(os.environ["REDMINE_REQUEST_INSTRUCTIONS"]) as f:
        REDMINE_REQUEST_INSTRUCTIONS = f.read()
else:
    REDMINE_REQUEST_INSTRUCTIONS = ""


# Core
def request(path: str, method: str = 'get', data: dict = None, params: dict = None,
            content_type: str = 'application/json', content: bytes = None) -> dict:
    headers = {
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': content_type,
        **REDMINE_HEADERS
    }
    url = urljoin(REDMINE_URL, path.lstrip('/'))

    try:
        response = httpx.request(method=method.lower(), url=url, json=data, params=params, headers=headers,
                                 content=content, timeout=60.0, verify=not REDMINE_DANGEROUSLY_ACCEPT_INVALID_CERTS)
        response.raise_for_status()

        body = None
        if response.content:
            try:
                body = response.json()
            except ValueError:
                body = response.content

        return {"status_code": response.status_code, "body": body, "error": ""}
    except Exception as e:
        try:
            status_code = e.response.status_code
        except:
            status_code = 0

        try:
            body = e.response.json()
        except:
            try:
                body = e.response.text
            except:
                body = None

        return {"status_code": status_code, "body": body, "error": f"{e.__class__.__name__}: {e}"}
        
def format_response(obj):
    """Format response as YAML or JSON based on REDMINE_RESPONSE_FORMAT env var."""
    if REDMINE_RESPONSE_FORMAT == 'json':
        return json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    # YAML: Allow direct Unicode output, prevent line wrapping for long lines, and avoid automatic key sorting.
    return yaml.safe_dump(obj, allow_unicode=True, sort_keys=False, width=4096)


def wrap_insecure_content(content: str) -> str:
    """Wrap content that may contain user-generated data with security tags to prevent prompt injection."""
    tag_id = uuid.uuid4().hex[:16]
    return f"<insecure-content-{tag_id}>\n{content}\n</insecure-content-{tag_id}>"


def validate_path(file_path: str, must_exist: bool = True) -> tuple[str | None, pathlib.Path | None]:
    """
    Validate and resolve a file path.
    Returns (None, resolved_path) on success, (error_message, None) on failure.
    """
    # Require allowed directories to be configured (secure by default)
    if not REDMINE_ALLOWED_DIRECTORIES:
        return "File operations disabled: REDMINE_ALLOWED_DIRECTORIES not configured", None

    try:
        path = pathlib.Path(file_path).expanduser().resolve()
    except Exception as e:
        return f"Invalid path: {file_path} ({e})", None

    if not path.is_absolute():
        return f"Path must be absolute, got: {file_path}", None

    # Check path is within allowed directories
    if not any(path.is_relative_to(allowed) for allowed in REDMINE_ALLOWED_DIRECTORIES):
        return f"Path not in allowed directories: {file_path}", None

    if must_exist and not path.exists():
        return f"File not found: {path}", None

    return None, path

# Metadata lookups (lazily fetched once per process, shared across all clients)
METADATA_SOURCES = {
    'status': ('issue_statuses.json', 'issue_statuses'),
    'tracker': ('trackers.json', 'trackers'),
    'priority': ('enumerations/issue_priorities.json', 'issue_priorities'),
    'activity': ('enumerations/time_entry_activities.json', 'time_entry_activities'),
}
METADATA_CACHE = {}
METADATA_LOCK = threading.Lock()


def metadata(kind: str) -> list:
    """Return [{id, name}, ...] for an enumeration, cached. Empty list if Redmine is unreachable."""
    if kind in METADATA_CACHE:
        return METADATA_CACHE[kind]

    with METADATA_LOCK:
        if kind in METADATA_CACHE:
            return METADATA_CACHE[kind]

        path, key = METADATA_SOURCES[kind]
        response = request(path)
        if response["status_code"] != 200 or not isinstance(response["body"], dict):
            return []  # Not cached, so a later call retries

        METADATA_CACHE[kind] = response["body"].get(key, [])
        return METADATA_CACHE[kind]


def resolve(kind: str, value) -> tuple[str | None, int | None]:
    """Resolve a name or numeric id to an id. Returns (error, id); (None, None) when value is None."""
    if value is None:
        return None, None

    text = str(value).strip()
    if text.isdigit():
        return None, int(text)

    for item in metadata(kind):
        if item.get("name", "").lower() == text.lower():
            return None, item["id"]

    known = ", ".join(item.get("name", "") for item in metadata(kind)) or "none available"
    return f"Unknown {kind}: {value!r}. Known {kind}s: {known}", None


def resolve_user(value) -> tuple[str | None, int | str | None]:
    """Resolve a user id or the literal 'me' to a user id."""
    if value is None:
        return None, None

    text = str(value).strip()
    if text.isdigit():
        return None, int(text)
    if text.lower() == "me":
        response = request("users/current.json")
        if response["status_code"] != 200:
            return f"Could not resolve 'me': {response['error'] or response['status_code']}", None
        return None, response["body"]["user"]["id"]

    return f"User must be a numeric id or 'me', got {value!r}", None


def resolve_project(project) -> str | None:
    """Explicit project wins, else REDMINE_PROJECT. 'all' clears the default. None means all projects."""
    value = str(project if project is not None else REDMINE_PROJECT).strip()
    return None if not value or value.lower() == "all" else value



# Tools
mcp = FastMCP("Redmine MCP server", stateless_http=True, json_response=True)
get_logger(__name__).info(f"Starting MCP Redmine version {VERSION}")

@mcp.tool(description="""
Make a request to the Redmine API

Args:
    path: API endpoint path (e.g. '/issues.json')
    method: HTTP method to use (default: 'get')
    data: Dictionary for request body (for POST/PUT)
    params: Dictionary for query parameters

Returns:
    str: YAML string containing response status code, body and error message

{}""".format(REDMINE_REQUEST_INSTRUCTIONS).strip())
    
def redmine_request(path: str, method: str = 'get', data: dict = None, params: dict = None) -> str:
    return wrap_insecure_content(format_response(request(path, method=method, data=data, params=params)))

@mcp.tool()
def redmine_paths_list() -> str:
    """Return a list of available API paths from OpenAPI spec
    
    Retrieves all endpoint paths defined in the Redmine OpenAPI specification. Remember that you can use the
    redmine_paths_info tool to get the full specfication for a path.
    
    Returns:
        str: YAML string containing a list of path templates (e.g. '/issues.json')
    """
    return format_response(list(SPEC['paths'].keys()))

@mcp.tool()
def redmine_paths_info(path_templates: list) -> str:
    """Get full path information for given path templates
    
    Args:
        path_templates: List of path templates (e.g. ['/issues.json', '/projects.json'])
        
    Returns:
        str: YAML string containing API specifications for the requested paths
    """
    info = {}
    for path in path_templates:
        if path in SPEC['paths']:
            info[path] = SPEC['paths'][path]

    return format_response(info)

@mcp.tool()
def redmine_upload(file_path: str, description: str = None) -> str:
    """
    Upload a file to Redmine and get a token for attachment

    Args:
        file_path: Fully qualified path to the file to upload (must be within REDMINE_ALLOWED_DIRECTORIES)
        description: Optional description for the file

    Returns:
        str: YAML string containing response status code, body and error message
             The body contains the attachment token
    """
    error, path = validate_path(file_path, must_exist=True)
    if error:
        return format_response({"status_code": 0, "body": None, "error": error})

    try:
        params = {'filename': path.name}
        if description:
            params['description'] = description

        with open(path, 'rb') as f:
            file_content = f.read()

        result = request(path='uploads.json', method='post', params=params,
                         content_type='application/octet-stream', content=file_content)
        return format_response(result)
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"{e.__class__.__name__}: {e}"})

@mcp.tool()
def redmine_download(attachment_id: int, save_path: str, filename: str = None) -> str:
    """
    Download an attachment from Redmine and save it to a local file

    Args:
        attachment_id: The ID of the attachment to download
        save_path: Fully qualified path where the file should be saved to (must be within REDMINE_ALLOWED_DIRECTORIES)
        filename: Optional filename to use for the attachment. If not provided,
                 will be determined from attachment data or URL

    Returns:
        str: YAML string containing download status, file path, and any error messages
    """
    error, path = validate_path(save_path, must_exist=False)
    if error:
        return format_response({"status_code": 0, "body": None, "error": error})

    if path.is_dir():
        return format_response({"status_code": 0, "body": None, "error": f"Path can't be a directory: {save_path}"})

    try:
        if not filename:
            attachment_response = request(f"attachments/{attachment_id}.json", "get")
            if attachment_response["status_code"] != 200:
                return format_response(attachment_response)

            filename = attachment_response["body"]["attachment"]["filename"]

        response = request(f"attachments/download/{attachment_id}/{filename}", "get",
                           content_type="application/octet-stream")
        if response["status_code"] != 200 or not response["body"]:
            return format_response(response)

        # Create parent directories if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'wb') as f:
            f.write(response["body"])

        return format_response({"status_code": 200, "body": {"saved_to": str(path), "filename": filename}, "error": ""})
    except Exception as e:
        return format_response({"status_code": 0, "body": None, "error": f"{e.__class__.__name__}: {e}"})

# Curated tools
PROJECT_NOTE = (
    f"Optional, defaults to the configured project {REDMINE_PROJECT!r}. Pass 'all' to span every project."
    if REDMINE_PROJECT else
    "Optional project id or identifier. Omitted means every project."
)


@mcp.tool()
def redmine_metadata() -> str:
    """Get the issue statuses, trackers, priorities and time entry activities of this Redmine instance

    Call this once before creating or updating issues so names map to the right ids. The curated tools accept
    names directly, so this is mainly useful for knowing which values exist.

    Returns:
        str: YAML string with the available enumerations, the current user and the default project
    """
    body = {kind: [{"id": i["id"], "name": i.get("name")} for i in metadata(kind)] for kind in METADATA_SOURCES}
    body["default_project"] = REDMINE_PROJECT or None

    current = request("users/current.json")
    if current["status_code"] == 200:
        body["current_user"] = {k: current["body"]["user"].get(k) for k in ("id", "login", "firstname", "lastname")}

    return wrap_insecure_content(format_response({"status_code": 200, "body": body, "error": ""}))


@mcp.tool(description="""
Search issues with the common filters

Args:
    query: Text to match against the issue subject (substring match)
    project: {}
    status: 'open' (default), 'closed', 'all', or a status name/id such as 'In Progress'
    assigned_to: User id or 'me'
    tracker: Tracker name or id, e.g. 'Bug'
    priority: Priority name or id, e.g. 'High'
    sort: Sort order (default 'updated_on:desc')
    limit: Max issues to return, capped at 100 (default 25)
    offset: Pagination offset

Returns:
    str: YAML string containing response status code, body and error message
""".format(PROJECT_NOTE).strip())
def redmine_search_issues(query: str = None, project: str = None, status: str = "open", assigned_to: str = None,
                          tracker: str = None, priority: str = None, sort: str = "updated_on:desc",
                          limit: int = 25, offset: int = 0) -> str:
    params = {"limit": max(1, min(limit, 100)), "offset": offset, "sort": sort}

    if project_id := resolve_project(project):
        params["project_id"] = project_id
    if query:
        params["subject"] = f"~{query}"

    # 'open'/'closed'/'all' are Redmine's own filter values; anything else is a status name or id
    status_text = (status or "open").strip().lower()
    if status_text in ("open", "closed"):
        params["status_id"] = status_text
    elif status_text not in ("all", "*"):
        error, status_id = resolve("status", status)
        if error:
            return format_response({"status_code": 0, "body": None, "error": error})
        params["status_id"] = status_id

    for name, kind, value in (("assigned_to_id", "user", assigned_to), ("tracker_id", "tracker", tracker),
                              ("priority_id", "priority", priority)):
        if value is None:
            continue
        error, resolved = resolve_user(value) if kind == "user" else resolve(kind, value)
        if error:
            return format_response({"status_code": 0, "body": None, "error": error})
        params[name] = resolved

    return wrap_insecure_content(format_response(request("issues.json", params=params)))


@mcp.tool()
def redmine_get_issue(issue_id: int, include: str = "journals,attachments,relations") -> str:
    """Get a single issue with its notes, attachments and relations

    Args:
        issue_id: The issue id
        include: Comma separated associations to include; pass '' for just the issue fields.
                 Available: journals, attachments, relations, children, watchers, changesets

    Returns:
        str: YAML string containing response status code, body and error message
    """
    params = {"include": include} if include else None
    return wrap_insecure_content(format_response(request(f"issues/{issue_id}.json", params=params)))


@mcp.tool(description="""
Create an issue

Args:
    subject: Issue title (required)
    description: Issue body, supports the wiki/markdown syntax of the instance
    project: {}
    tracker: Tracker name or id, e.g. 'Bug'
    priority: Priority name or id, e.g. 'High'
    assigned_to: User id or 'me'
    parent_issue_id: Parent issue id for subtasks
    start_date: YYYY-MM-DD
    due_date: YYYY-MM-DD
    estimated_hours: Estimate in decimal hours
    custom_fields: List of {{"id": int, "value": any}} for custom fields

Returns:
    str: YAML string containing response status code, body and error message
""".format(PROJECT_NOTE).strip())
def redmine_create_issue(subject: str, description: str = None, project: str = None, tracker: str = None,
                         priority: str = None, assigned_to: str = None, parent_issue_id: int = None,
                         start_date: str = None, due_date: str = None, estimated_hours: float = None,
                         custom_fields: list = None) -> str:
    project_id = resolve_project(project)
    if not project_id:
        return format_response({"status_code": 0, "body": None,
                                "error": "No project given and REDMINE_PROJECT is not configured"})

    issue = {"project_id": project_id, "subject": subject}
    for key, value in (("description", description), ("parent_issue_id", parent_issue_id),
                       ("start_date", start_date), ("due_date", due_date),
                       ("estimated_hours", estimated_hours), ("custom_fields", custom_fields)):
        if value is not None:
            issue[key] = value

    for key, kind, value in (("tracker_id", "tracker", tracker), ("priority_id", "priority", priority),
                             ("assigned_to_id", "user", assigned_to)):
        if value is None:
            continue
        error, resolved = resolve_user(value) if kind == "user" else resolve(kind, value)
        if error:
            return format_response({"status_code": 0, "body": None, "error": error})
        issue[key] = resolved

    return wrap_insecure_content(format_response(request("issues.json", method="post", data={"issue": issue})))


@mcp.tool()
def redmine_update_issue(issue_id: int, notes: str = None, subject: str = None, description: str = None,
                         status: str = None, priority: str = None, assigned_to: str = None,
                         done_ratio: int = None, due_date: str = None, private_notes: bool = False) -> str:
    """Update an issue and/or add a note to it

    Args:
        issue_id: The issue id
        notes: Comment to append to the issue journal
        subject: New title
        description: New body
        status: Status name or id, e.g. 'Resolved'
        priority: Priority name or id, e.g. 'High'
        assigned_to: User id or 'me'
        done_ratio: Percent done, 0-100
        due_date: YYYY-MM-DD
        private_notes: Mark the note as private

    Returns:
        str: YAML string containing response status code, body and error message
    """
    issue = {}
    for key, value in (("notes", notes), ("subject", subject), ("description", description),
                       ("done_ratio", done_ratio), ("due_date", due_date)):
        if value is not None:
            issue[key] = value

    for key, kind, value in (("status_id", "status", status), ("priority_id", "priority", priority),
                             ("assigned_to_id", "user", assigned_to)):
        if value is None:
            continue
        error, resolved = resolve_user(value) if kind == "user" else resolve(kind, value)
        if error:
            return format_response({"status_code": 0, "body": None, "error": error})
        issue[key] = resolved

    if not issue:
        return format_response({"status_code": 0, "body": None, "error": "Nothing to update"})
    if private_notes and notes:
        issue["private_notes"] = True

    return format_response(request(f"issues/{issue_id}.json", method="put", data={"issue": issue}))


@mcp.tool(description="""
Log time on an issue or a project

Args:
    hours: Hours spent, decimal (required)
    issue_id: Issue to log on. Either this or project must resolve to something
    project: {}
    activity: Activity name or id, e.g. 'Development'
    comments: What was done
    spent_on: YYYY-MM-DD, defaults to today on the Redmine side

Returns:
    str: YAML string containing response status code, body and error message
""".format(PROJECT_NOTE).strip())
def redmine_log_time(hours: float, issue_id: int = None, project: str = None, activity: str = None,
                     comments: str = None, spent_on: str = None) -> str:
    entry = {"hours": hours}
    if issue_id is not None:
        entry["issue_id"] = issue_id
    elif project_id := resolve_project(project):
        entry["project_id"] = project_id
    else:
        return format_response({"status_code": 0, "body": None,
                                "error": "Give an issue_id or a project (or configure REDMINE_PROJECT)"})

    for key, value in (("comments", comments), ("spent_on", spent_on)):
        if value is not None:
            entry[key] = value

    if activity is not None:
        error, activity_id = resolve("activity", activity)
        if error:
            return format_response({"status_code": 0, "body": None, "error": error})
        entry["activity_id"] = activity_id

    return format_response(request("time_entries.json", method="post", data={"time_entry": entry}))


@mcp.tool()
def redmine_list_projects(limit: int = 100) -> str:
    """List the projects visible to the API user

    Args:
        limit: Max projects to return, capped at 100 (default 100)

    Returns:
        str: YAML string containing response status code, body and error message
    """
    response = request("projects.json", params={"limit": max(1, min(limit, 100))})
    if response["status_code"] == 200 and isinstance(response["body"], dict):
        # Trim to the fields needed to pick a project
        response["body"] = {
            "total_count": response["body"].get("total_count"),
            "projects": [{k: p.get(k) for k in ("id", "identifier", "name")}
                         for p in response["body"].get("projects", [])],
        }

    return wrap_insecure_content(format_response(response))


def main():
    """Main entry point for the mcp-redmine package."""
    import argparse
    parser = argparse.ArgumentParser(description="MCP Redmine Server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio",
                        help="Transport type (default: stdio)")
    parser.add_argument("--host", default="0.0.0.0", help="Host for HTTP transports (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port for HTTP transports (default: 8000)")
    args = parser.parse_args()

    if args.transport in ("sse", "streamable-http"):
        mcp.settings.host = args.host
        mcp.settings.port = args.port
    mcp.run(transport=args.transport)

if __name__ == "__main__":
    main()
