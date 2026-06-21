"""
Twitter/X MCP Connector

Native connector that wraps the xdk Python SDK as MCP tools.
Auto-registers on import via NativeConnector.__init_subclass__.

xdk uses synchronous HTTP (requests), so all calls are wrapped in
asyncio.run_in_executor() to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from base64 import b64decode, b64encode
from typing import Any

from requests import HTTPError
from xdk import Client as XClient
from xdk.media.models import UploadRequest
from xdk.posts.models import CreateRequest

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.models.connector_config import AppConnectorCredentials, ConnectorMeta

logger = logging.getLogger(__name__)

# === CONSTANTS ===

MAX_TWEET_LENGTH = 280
MAX_RESULTS_CAP = 100
DEFAULT_MAX_RESULTS = 10
MAX_THREAD_TWEETS = 25  # cap sequential posts so a runaway thread can't drain the write quota

# X wraps every URL in a t.co short link of fixed display length, so a URL of
# any actual length counts as this many weighted characters.
URL_WEIGHTED_LENGTH = 23
# Code points outside URLs that weigh 1 in X's twitter-text v3 config; everything
# else (CJK, emoji, symbols) weighs 2.
DEFAULT_CHAR_WEIGHT = 1
WIDE_CHAR_WEIGHT = 2
# Inclusive code-point ranges that weigh 1 (twitter-text v3 default weight ranges).
WEIGHT_ONE_RANGES = (
    (0x0000, 0x10FF),
    (0x2000, 0x200A),
    (0x2010, 0x201F),
    (0x2032, 0x2037),
)
_URL_RE = re.compile(r"https?://\S+")

# X API per-endpoint minimums for max_results — sending below these 400s upstream.
# Timeline (GET /2/users/:id/tweets) requires >= 5; recent search
# (GET /2/tweets/search/recent) requires >= 10. xdk forwards max_results verbatim.
MIN_TIMELINE_RESULTS = 5
MIN_SEARCH_RESULTS = 10

_TWEET_ID_RE = re.compile(r"^\d{1,20}$")

# X media: up to 4 images per tweet, 5 MB each. Images are uploaded first (base64),
# then the returned media_ids are attached to the tweet.
MAX_IMAGES_PER_TWEET = 4
MAX_IMAGE_BYTES = 5 * 1024 * 1024
# Bound the base64 string before decoding (enforced in _upload_image; the schema maxLength
# is advisory -- the broker does not validate inputs against it). base64 inflates ~4/3:
# ceil(bytes / 3) * 4.
_MAX_IMAGE_BASE64_CHARS = -(-MAX_IMAGE_BYTES // 3) * 4

# === TOOL METADATA ===

_POST_TWEET_META = NativeToolMeta(
    name="post_tweet",
    description=(
        "Post a tweet to X/Twitter. Text must be 280 characters or fewer. "
        "Returns the created tweet object {id, text}. Raises if X reports the "
        "post failed."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Tweet text (max 280 chars)"},
        },
        "required": ["text"],
    },
)

_POST_IMAGE_TWEET_META = NativeToolMeta(
    name="post_image_tweet",
    description=(
        "Post a tweet to X/Twitter with 1-4 attached images (PNG/JPG/GIF/WEBP), each supplied "
        "as base64-encoded bytes (up to 5 MB each). Text is optional and must be 280 characters "
        "or fewer. Returns the created tweet object."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "images_base64": {
                "type": "array",
                "items": {"type": "string", "maxLength": _MAX_IMAGE_BASE64_CHARS},
                "minItems": 1,
                "maxItems": MAX_IMAGES_PER_TWEET,
                "description": "1-4 base64-encoded images (PNG/JPG/GIF/WEBP, up to 5 MB each)",
            },
            "text": {"type": "string", "description": "Tweet text (optional, max 280 chars)"},
        },
        "required": ["images_base64"],
    },
)

_GET_ME_META = NativeToolMeta(
    name="get_me",
    description="Get the authenticated user's X/Twitter profile information.",
    input_schema={
        "type": "object",
        "properties": {},
    },
)

_DELETE_TWEET_META = NativeToolMeta(
    name="delete_tweet",
    description="Delete a tweet by its ID.",
    input_schema={
        "type": "object",
        "properties": {
            "tweet_id": {"type": "string", "description": "ID of the tweet to delete"},
        },
        "required": ["tweet_id"],
    },
)

_GET_MY_TWEETS_META = NativeToolMeta(
    name="get_my_tweets",
    description="Get recent tweets from the authenticated user. Returns up to max_results tweets.",
    input_schema={
        "type": "object",
        "properties": {
            "max_results": {
                "type": "integer",
                "description": "Number of tweets to return (5-100, default 10)",
                "default": 10,
            },
        },
    },
)

_SEARCH_TWEETS_META = NativeToolMeta(
    name="search_tweets",
    description="Search recent tweets on X/Twitter matching a query string.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "max_results": {
                "type": "integer",
                "description": "Number of tweets to return (10-100, default 10)",
                "default": 10,
            },
        },
        "required": ["query"],
    },
)

_POST_THREAD_META = NativeToolMeta(
    name="post_thread",
    description=(
        "Post a thread to X/Twitter — an ordered list of tweets where the first is the root "
        "and each subsequent tweet is posted as a reply to the previous one, forming a connected "
        "chain. Each tweet must be 280 characters or fewer, and a thread may contain at most "
        "25 tweets."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "tweets": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "maxItems": MAX_THREAD_TWEETS,  # mirror the validator's cap in the LLM-facing schema
                "description": "Ordered tweet texts; index 0 is the root, each next one replies to it",
            },
        },
        "required": ["tweets"],
    },
)

_REPLY_TO_TWEET_META = NativeToolMeta(
    name="reply_to_tweet",
    description=(
        "Reply to (comment on) an existing tweet on X/Twitter. Posts a new tweet as a reply to "
        "the given tweet ID. Reply text must be 280 characters or fewer."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Reply text (max 280 chars)"},
            "tweet_id": {"type": "string", "description": "ID of the tweet to reply to"},
        },
        "required": ["text", "tweet_id"],
    },
)


# === SYNC HELPERS (run in executor) ===


def _create_post(client: XClient, text: str, in_reply_to: str | None = None) -> dict[str, Any]:
    """Create a post (optionally as a reply) and return its data as a dict.

    A plain dict is used for `reply` (Pydantic coerces it) to avoid importing the
    nested CreateRequestReply model, which xdk does not export at module level.
    """
    body_fields: dict[str, Any] = {"text": text}
    if in_reply_to is not None:
        body_fields["reply"] = {"in_reply_to_tweet_id": in_reply_to}
    return _model_to_dict(client.posts.create(body=CreateRequest(**body_fields)))


def _unwrap_tweet(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return the created tweet's data, or raise a sanitized ValueError.

    X reports creation failures in the envelope's `errors` array — surfaced as the
    connector's client-facing error channel rather than a tweet that was never posted.
    An envelope with neither `data` nor `errors` (an unusual malformed 200) would otherwise
    reach dict(None) and surface a TypeError as an internal error.
    """
    tweet = envelope.get("data")
    if tweet is None:
        if envelope.get("errors"):
            raise ValueError(_summarize_post_errors(envelope["errors"]))
        raise ValueError("X returned no tweet data")
    return _model_to_dict(tweet)


def _post_tweet_sync(access_token: str, text: str) -> dict[str, Any]:
    """Post a tweet via xdk. Returns the unwrapped tweet object ({id, text})."""
    envelope = _create_post(XClient(access_token=access_token), text)
    return _unwrap_tweet(envelope)


def _describe_media_http_error(exc: HTTPError) -> str:
    """Turn an HTTP error from the media-upload call into an actionable client message.

    A 403 here is almost always the missing media.write scope; xdk raises a bare
    requests.HTTPError, so without this the connector would surface an opaque "HTTPError".
    """
    status = exc.response.status_code if exc.response is not None else None
    if status == 403:  # noqa: PLR2004 -- HTTP status code
        return (
            "X rejected the media upload (HTTP 403 Forbidden) -- the Twitter connection is "
            "likely missing the media.write scope; reconnect to grant it (see SETUP.md)"
        )
    if status == 401:  # noqa: PLR2004 -- HTTP status code
        return "X media upload was unauthorized (HTTP 401) -- reconnect the Twitter account"
    return f"X media upload failed (HTTP {status})" if status else "X media upload failed"


def _detect_image_mime(raw_bytes: bytes) -> str:
    """Sniff the image MIME from its magic bytes -- X needs media_type on the upload."""
    if raw_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw_bytes[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP":
        return "image/webp"
    raise ValueError("Unsupported image format (expected PNG, JPEG, GIF, or WEBP)")


def _upload_image(client: XClient, image_base64: str) -> str:
    """Validate and upload one image; return its media_id.

    X takes the media as base64 in a JSON body (xdk serializes the UploadRequest), so the
    base64 is kept for the call but decoded first to enforce the 5 MB limit and sniff the
    MIME -- both before the bytes leave the process.
    """
    # The schema maxLength is advisory (the broker does not validate inputs against it), so
    # reject an over-long encoded string before decoding -- never expand an oversized payload.
    if len(image_base64) > _MAX_IMAGE_BASE64_CHARS:
        raise ValueError(f"An image exceeds the {MAX_IMAGE_BYTES}-byte (5 MB) upload limit")
    try:
        raw_bytes = b64decode(image_base64, validate=True)
    except ValueError as exc:  # binascii.Error subclasses ValueError
        raise ValueError("An image is not valid base64") from exc
    if not raw_bytes:
        raise ValueError("An image is empty")
    if len(raw_bytes) > MAX_IMAGE_BYTES:
        raise ValueError(
            f"An image is {len(raw_bytes)} bytes; the X limit is {MAX_IMAGE_BYTES} bytes (5 MB)"
        )
    mime = _detect_image_mime(raw_bytes)
    category = "tweet_gif" if mime == "image/gif" else "tweet_image"
    try:
        response = client.media.upload(
            body=UploadRequest(media=image_base64, media_category=category, media_type=mime)
        )
    except HTTPError as exc:
        raise ValueError(_describe_media_http_error(exc)) from exc
    media_id = response.data.id if response.data else None
    if not media_id:
        errors = getattr(response, "errors", None)
        if errors:
            raise ValueError(_summarize_post_errors(errors, "the media upload"))
        raise ValueError("X returned no media id")
    return str(media_id)


def _post_image_tweet_sync(
    access_token: str, text: str, images_base64: list[str]
) -> dict[str, Any]:
    """Upload 1-4 images then post a tweet referencing them. Returns the tweet object."""
    client = XClient(access_token=access_token)
    media_ids = [_upload_image(client, image) for image in images_base64]
    # Omit `text` when empty: an image-only tweet is valid, but X rejects an empty `text`
    # field. media is a plain dict (Pydantic coerces it) -- the same pattern _create_post uses
    # for `reply`, avoiding an import of the nested CreateRequestMedia model.
    body_fields: dict[str, Any] = {"media": {"media_ids": media_ids}}
    if text:
        body_fields["text"] = text
    envelope = _model_to_dict(client.posts.create(body=CreateRequest(**body_fields)))
    return _unwrap_tweet(envelope)


def _post_thread_sync(access_token: str, tweets: list[str]) -> dict[str, Any]:
    """Post tweets as a chained thread, each replying to the previous.

    On a mid-thread post failure (after at least one tweet posted), returns a partial-state
    structure so the already-posted IDs survive instead of being lost to an exception.
    A failure on the very first post propagates — nothing was posted.
    """
    client = XClient(access_token=access_token)
    posted: list[dict[str, str]] = []
    reply_to: str | None = None
    for index, text in enumerate(tweets):
        try:
            created = _create_post(client, text, reply_to)
        except Exception as exc:  # noqa: BLE001 — partial-state reporting must capture any post failure
            if not posted:
                raise
            return {
                "status": "partial",
                "posted": posted,
                "failed_at_index": index,
                "error": str(exc),
            }
        # ID extraction reads the response of an already-posted tweet — keep it outside the
        # try so a malformed-response error never marks a live tweet as failed (which would
        # double-post on retry). A bad shape here propagates rather than mislabeling.
        tweet_id = _extract_tweet_id(created)
        posted.append({"id": tweet_id, "text": text})
        reply_to = tweet_id
    return {"status": "complete", "count": len(posted), "thread": posted}


def _reply_to_tweet_sync(access_token: str, text: str, tweet_id: str) -> dict[str, Any]:
    """Reply to an existing tweet via xdk. Returns the reply's data as a dict."""
    return _create_post(XClient(access_token=access_token), text, tweet_id)


def _get_me_sync(access_token: str) -> dict[str, Any]:
    """Get authenticated user profile via xdk."""
    client = XClient(access_token=access_token)
    response = client.users.get_me()
    return _model_to_dict(response.data)


def _delete_tweet_sync(access_token: str, tweet_id: str) -> dict[str, Any]:
    """Delete a tweet via xdk."""
    client = XClient(access_token=access_token)
    response = client.posts.delete(id=tweet_id)
    deleted = response.data.deleted if response.data else False
    return {"tweet_id": tweet_id, "deleted": deleted}


def _get_my_tweets_sync(access_token: str, max_results: int) -> list[dict[str, Any]]:
    """Get authenticated user's recent tweets via xdk."""
    client = XClient(access_token=access_token)
    user_response = client.users.get_me()
    user_id = _extract_user_id(user_response.data)

    tweets: list[dict[str, Any]] = []
    for page in client.users.get_posts(id=user_id, max_results=max_results):
        if page.data:
            tweets.extend(_model_to_dict(tweet) for tweet in page.data)
        break  # first page only
    return tweets


def _search_tweets_sync(access_token: str, query: str, max_results: int) -> list[dict[str, Any]]:
    """Search recent tweets via xdk."""
    client = XClient(access_token=access_token)
    tweets: list[dict[str, Any]] = []
    for page in client.posts.search_recent(query=query, max_results=max_results):
        if page.data:
            tweets.extend(_model_to_dict(tweet) for tweet in page.data)
        break  # first page only
    return tweets


# === SERIALIZATION HELPERS ===


def _model_to_dict(model: Any) -> Any:
    """Convert a Pydantic model or dict-like object to a plain dict."""
    if isinstance(model, dict):
        return model
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return dict(model)


def _summarize_post_errors(errors: Any, subject: str = "the tweet") -> str:
    """Summarize X's `errors` array into a sanitized client-facing message.

    `subject` names what X rejected -- "the tweet" by default, or "the media upload" when the
    failure is on the upload call, before any tweet is attempted. Only the human-readable
    `title` of each error is surfaced. X error objects can carry URLs and resource identifiers
    in other fields; those are dropped so the ValueError stays free of URLs and tokens per the
    connector's error-channel rules.
    """
    titles = [
        title for error in errors if isinstance(error, dict) and (title := error.get("title"))
    ]
    summary = "; ".join(titles) if titles else "unknown error"
    return f"X rejected {subject}: {summary}"


def _weighted_tweet_length(text: str) -> int:
    """Compute X's weighted tweet length (twitter-text v3 config).

    URLs with an explicit scheme count as a fixed 23 (t.co wrapping). Outside URLs,
    code points in the ranges below weigh 1; everything else (CJK, emoji, symbols)
    weighs 2.

    Known approximations, both of which over-count and therefore REJECT early
    rather than accept an invalid tweet (X's own response stays authoritative):
    - Bare-domain URLs without a scheme (e.g. ``example.com``) are not detected as
      URLs and are counted per character, over-counting versus X's 23.
    - Multi-code-point emoji sequences (ZWJ joins, skin-tone modifiers) are counted
      per code point at weight 2 each; X counts 2 per emoji grapheme, so we
      over-count compound emoji.
    """
    weighted = 0
    cursor = 0
    for match in _URL_RE.finditer(text):
        weighted += _weigh_plain_run(text[cursor : match.start()])
        weighted += URL_WEIGHTED_LENGTH
        cursor = match.end()
    weighted += _weigh_plain_run(text[cursor:])
    return weighted


def _weigh_plain_run(run: str) -> int:
    """Weight a non-URL text run per the twitter-text v3 weight-1 code point ranges."""
    return sum(
        DEFAULT_CHAR_WEIGHT if _is_weight_one(ord(char)) else WIDE_CHAR_WEIGHT for char in run
    )


def _is_weight_one(code_point: int) -> bool:
    """Whether a code point falls in a twitter-text v3 weight-1 range."""
    return any(low <= code_point <= high for low, high in WEIGHT_ONE_RANGES)


def _extract_user_id(user_data: Any) -> str:
    """Extract user ID from get_me response data."""
    if isinstance(user_data, dict):
        return str(user_data["id"])
    if hasattr(user_data, "id"):
        return str(user_data.id)
    raise ValueError("Cannot extract user ID from response")


def _extract_tweet_id(create_response: dict[str, Any]) -> str:
    """Pull the tweet ID from a posts.create response of shape {"data": {"id": ...}}."""
    tweet_data = create_response.get("data")
    if not isinstance(tweet_data, dict) or "id" not in tweet_data:
        raise ValueError(f"Unexpected create response shape: {create_response!r}")
    return str(tweet_data["id"])


def _validate_thread_tweets(tweets: Any) -> None:
    """Pre-flight the whole batch before any tweet is posted.

    Validating up front turns avoidable mid-thread failures (e.g. an over-length tweet
    halfway down) into a clean rejection with nothing posted. Uses X's weighted
    length so wide characters and URLs are measured the same way as post_tweet.
    """
    if not isinstance(tweets, list) or not tweets:
        raise ValueError("tweets must be a non-empty list")
    if len(tweets) > MAX_THREAD_TWEETS:
        raise ValueError(f"Thread exceeds {MAX_THREAD_TWEETS} tweets ({len(tweets)} given)")
    for position, text in enumerate(tweets, start=1):
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"Tweet {position} is empty")
        weighted_length = _weighted_tweet_length(text)
        if weighted_length > MAX_TWEET_LENGTH:
            raise ValueError(
                f"Tweet {position} exceeds {MAX_TWEET_LENGTH} characters "
                f"({weighted_length} weighted given)"
            )


def _clamp_max_results(max_results: int, minimum: int) -> int:
    """Clamp max_results to [minimum, MAX_RESULTS_CAP].

    `minimum` is per-endpoint (timeline vs search) because the X API enforces
    different floors and rejects values below them.
    """
    return max(minimum, min(max_results, MAX_RESULTS_CAP))


def _mcp_text_content(payload: Any) -> list[dict[str, Any]]:
    """Wrap a payload as MCP text content blocks."""
    return [{"type": "text", "text": json.dumps(payload, default=str)}]


# === CONNECTOR ===


class TwitterConnector(NativeConnector):
    """Twitter/X native connector — wraps xdk SDK as MCP tools.

    Uses OAuth 2.0 with PKCE. X requires HTTP Basic Auth for token exchange
    (base64-encoded client_id:client_secret in Authorization header).
    """

    meta = ConnectorMeta(
        name="twitter",
        display_name="Twitter/X",
        oauth_authorize_url="https://x.com/i/oauth2/authorize",
        oauth_token_url="https://api.x.com/2/oauth2/token",  # noqa: S106 — endpoint URL, not a password
        scopes=("tweet.read", "tweet.write", "users.read", "media.write", "offline.access"),
    )

    # --- OAuth override ---

    def build_token_request_auth(
        self,
        credentials: AppConnectorCredentials,
    ) -> tuple[dict, dict[str, str]]:
        """X requires HTTP Basic Auth for token exchange (client_secret_basic)."""
        encoded = b64encode(
            f"{credentials.client_id}:{credentials.client_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {encoded}"}, {}

    # --- MCP tools ---

    @native_tool(_POST_TWEET_META)
    async def post_tweet(self, *, access_token: str, text: str) -> list[dict[str, Any]]:
        """Post a tweet. Validates non-empty text and weighted length before calling X API."""
        if not text.strip():
            raise ValueError("Tweet text is empty")
        weighted_length = _weighted_tweet_length(text)
        if weighted_length > MAX_TWEET_LENGTH:
            raise ValueError(
                f"Tweet exceeds {MAX_TWEET_LENGTH} characters ({weighted_length} weighted given)"
            )
        loop = asyncio.get_running_loop()
        tweet_response = await loop.run_in_executor(None, _post_tweet_sync, access_token, text)
        return _mcp_text_content(tweet_response)

    @native_tool(_POST_IMAGE_TWEET_META)
    async def post_image_tweet(
        self, *, access_token: str, images_base64: list[str], text: str = ""
    ) -> list[dict[str, Any]]:
        """Post a tweet with 1-4 attached images. Validates count and text length before upload."""
        if not images_base64:
            raise ValueError("At least one image is required")
        if len(images_base64) > MAX_IMAGES_PER_TWEET:
            raise ValueError(
                f"At most {MAX_IMAGES_PER_TWEET} images per tweet ({len(images_base64)} given)"
            )
        weighted_length = _weighted_tweet_length(text)
        if weighted_length > MAX_TWEET_LENGTH:
            raise ValueError(
                f"Tweet exceeds {MAX_TWEET_LENGTH} characters ({weighted_length} weighted given)"
            )
        loop = asyncio.get_running_loop()
        tweet_response = await loop.run_in_executor(
            None, _post_image_tweet_sync, access_token, text, images_base64
        )
        return _mcp_text_content(tweet_response)

    @native_tool(_GET_ME_META)
    async def get_me(self, *, access_token: str) -> list[dict[str, Any]]:
        """Get authenticated user's profile."""
        loop = asyncio.get_running_loop()
        profile = await loop.run_in_executor(None, _get_me_sync, access_token)
        return _mcp_text_content(profile)

    @native_tool(_DELETE_TWEET_META)
    async def delete_tweet(self, *, access_token: str, tweet_id: str) -> list[dict[str, Any]]:
        """Delete a tweet by ID."""
        if not _TWEET_ID_RE.match(tweet_id):
            raise ValueError(f"Invalid tweet ID: {tweet_id!r}")
        loop = asyncio.get_running_loop()
        deletion = await loop.run_in_executor(None, _delete_tweet_sync, access_token, tweet_id)
        return _mcp_text_content(deletion)

    @native_tool(_GET_MY_TWEETS_META)
    async def get_my_tweets(
        self, *, access_token: str, max_results: int = DEFAULT_MAX_RESULTS
    ) -> list[dict[str, Any]]:
        """Get the authenticated user's recent tweets."""
        clamped = _clamp_max_results(max_results, MIN_TIMELINE_RESULTS)
        loop = asyncio.get_running_loop()
        tweets = await loop.run_in_executor(None, _get_my_tweets_sync, access_token, clamped)
        return _mcp_text_content(tweets)

    @native_tool(_SEARCH_TWEETS_META)
    async def search_tweets(
        self, *, access_token: str, query: str, max_results: int = DEFAULT_MAX_RESULTS
    ) -> list[dict[str, Any]]:
        """Search recent tweets matching a query."""
        clamped = _clamp_max_results(max_results, MIN_SEARCH_RESULTS)
        loop = asyncio.get_running_loop()
        tweets = await loop.run_in_executor(None, _search_tweets_sync, access_token, query, clamped)
        return _mcp_text_content(tweets)

    @native_tool(_POST_THREAD_META)
    async def post_thread(self, *, access_token: str, tweets: list[str]) -> list[dict[str, Any]]:
        """Post a chained thread. Validates the whole batch before posting anything."""
        _validate_thread_tweets(tweets)
        loop = asyncio.get_running_loop()
        thread = await loop.run_in_executor(None, _post_thread_sync, access_token, tweets)
        return _mcp_text_content(thread)

    @native_tool(_REPLY_TO_TWEET_META)
    async def reply_to_tweet(
        self, *, access_token: str, text: str, tweet_id: str
    ) -> list[dict[str, Any]]:
        """Reply to an existing tweet. Validates text is non-empty, length, and tweet ID format."""
        if not text.strip():
            raise ValueError("Reply text is empty")
        if len(text) > MAX_TWEET_LENGTH:
            raise ValueError(f"Reply exceeds {MAX_TWEET_LENGTH} characters ({len(text)} given)")
        if not _TWEET_ID_RE.match(tweet_id):
            raise ValueError(f"Invalid tweet ID: {tweet_id!r}")
        loop = asyncio.get_running_loop()
        reply = await loop.run_in_executor(None, _reply_to_tweet_sync, access_token, text, tweet_id)
        return _mcp_text_content(reply)
