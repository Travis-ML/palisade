"""palisade/__main__.py (Chapter 4). Chapter 5 extends this to start the GovernedLoop."""
import sys

from palisade.settings import PlaneBindingError, bind_plane, load_settings


def main() -> int:
    try:
        settings = load_settings()
        bound = bind_plane(settings)
    except PlaneBindingError as exc:
        print(f"palisade: refusing to start: {exc}", file=sys.stderr)
        return 2
    print(f"palisade: bound to the {bound.plane.value} plane as {bound.agent.agent_id}; "
          f"tools: {', '.join(bound.tools) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
