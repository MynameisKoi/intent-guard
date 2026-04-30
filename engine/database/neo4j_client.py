"""Neo4j graph writes for scan topology; read API for topology endpoint."""

import logging

from neo4j import GraphDatabase
from config import settings
from schemas.graph_nodes import GraphEdge, GraphNode, TopologyPayload

logger = logging.getLogger(__name__)


class Neo4jGraph:
    def __init__(self) -> None:
        self._driver = None
        drv = None
        try:
            drv = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )
            drv.verify_connectivity()
            self._driver = drv
            logger.info("Connected to Neo4j at %s", settings.neo4j_uri)
        except Exception as e:
            logger.warning("Neo4j unavailable (%s). Graph operations will be skipped.", e)
            if drv is not None:
                try:
                    drv.close()
                except Exception:
                    pass
            self._driver = None

    @property
    def available(self) -> bool:
        return self._driver is not None

    def close(self) -> None:
        if self._driver:
            self._driver.close()

    def write_topology(self, scan_id: str, topology: TopologyPayload) -> None:
        if not self._driver:
            return
        with self._driver.session() as session:
            session.execute_write(self._tx_write, scan_id, topology)

    @staticmethod
    def _tx_write(tx, scan_id: str, topology: TopologyPayload) -> None:
        tx.run(
            "MATCH (n:IGNode {scan_id: $sid}) DETACH DELETE n",
            sid=scan_id,
        )
        for n in topology.nodes:
            tx.run(
                """
                CREATE (node:IGNode {
                  scan_id: $scan_id,
                  id: $id,
                  label: $label,
                  kind: $kind,
                  path: $path,
                  is_source: $is_source
                })
                """,
                scan_id=scan_id,
                id=n.id,
                label=n.label,
                kind=n.kind,
                path=n.path or "",
                is_source=bool(n.is_source),
            )
            if n.kind == "agent":
                tx.run(
                    "MATCH (node:IGNode {scan_id: $sid, id: $id}) SET node:Agent",
                    sid=scan_id,
                    id=n.id,
                )
            elif n.kind == "tool":
                tx.run(
                    "MATCH (node:IGNode {scan_id: $sid, id: $id}) SET node:Tool",
                    sid=scan_id,
                    id=n.id,
                )
            elif n.kind == "prompt":
                tx.run(
                    "MATCH (node:IGNode {scan_id: $sid, id: $id}) SET node:Prompt",
                    sid=scan_id,
                    id=n.id,
                )
            elif n.kind == "permission":
                tx.run(
                    "MATCH (node:IGNode {scan_id: $sid, id: $id}) SET node:Permission",
                    sid=scan_id,
                    id=n.id,
                )
            elif n.kind == "task":
                tx.run(
                    "MATCH (node:IGNode {scan_id: $sid, id: $id}) SET node:Task",
                    sid=scan_id,
                    id=n.id,
                )
            if n.is_source:
                tx.run(
                    "MATCH (node:IGNode {scan_id: $sid, id: $id}) SET node:IGSource",
                    sid=scan_id,
                    id=n.id,
                )
        for e in topology.edges:
            tx.run(
                """
                MATCH (a:IGNode {scan_id: $scan_id, id: $src})
                MATCH (b:IGNode {scan_id: $scan_id, id: $tgt})
                MERGE (a)-[r:IG_EDGE {scan_id: $scan_id, id: $eid}]->(b)
                SET r.kind = $kind, r.variable_name = $variable_name
                """,
                scan_id=scan_id,
                src=e.source,
                tgt=e.target,
                eid=e.id,
                kind=e.kind,
                variable_name=e.variable_name,
            )

    def read_topology(
        self,
        scan_id: str,
        *,
        include_tests: bool = False,
        only_paths_of_interest: bool = True,
        debug: bool = False,
        depth: int = 4,
        limit: int = 500,
    ) -> TopologyPayload | None:
        if not self._driver:
            return None
        depth = max(1, min(int(depth), 8))
        limit = max(10, min(int(limit), 1000))
        use_paths = only_paths_of_interest and not debug
        if debug:
            lim_nodes = min(300, limit)
            lim_edges = min(900, lim_nodes * 3)
        else:
            lim_nodes = limit
            lim_edges = lim_nodes * 3
        with self._driver.session() as session:
            if use_paths:
                # Paths of Interest: entry-like nodes to security sinks, bounded by depth and size.
                nrows = list(
                    session.run(
                        f"""
                        MATCH p=(entry:IGNode {{scan_id: $sid}})-[:IG_EDGE*1..{depth}]->(sink:IGNode {{scan_id: $sid}})
                        WHERE (
                            entry.kind IN ['file', 'data', 'source', 'agent', 'prompt', 'task']
                            OR COALESCE(entry.is_source, false) = true
                            OR 'IGSource' IN labels(entry)
                            OR 'Agent' IN labels(entry)
                            OR 'Prompt' IN labels(entry)
                            OR 'Task' IN labels(entry)
                            OR toLower(entry.label) CONTAINS 'input'
                            OR toLower(entry.label) CONTAINS 'env'
                            OR toLower(entry.label) CONTAINS 'read'
                            OR toLower(entry.label) CONTAINS 'api'
                        )
                        AND (
                            sink.kind = 'external'
                            OR sink.kind IN ['tool', 'permission', 'task']
                            OR 'Tool' IN labels(sink)
                            OR 'Permission' IN labels(sink)
                            OR 'Task' IN labels(sink)
                            OR toLower(sink.label) CONTAINS 'http'
                            OR toLower(sink.label) CONTAINS 'subprocess'
                            OR toLower(sink.label) CONTAINS 'shell'
                            OR toLower(sink.label) CONTAINS 'eval'
                            OR toLower(sink.label) CONTAINS 'tool'
                        )
                        WITH collect(p) AS paths
                        UNWIND paths AS p
                        UNWIND nodes(p) AS n
                        WITH DISTINCT n
                        WHERE $include_tests OR n.path IS NULL OR NOT (
                            toLower(n.path) CONTAINS '/tests/' OR
                            toLower(n.path) CONTAINS '\\\\tests\\\\' OR
                            toLower(n.path) CONTAINS '/test_' OR
                            toLower(n.path) CONTAINS '\\\\test_' OR
                            toLower(n.path) ENDS WITH '/conftest.py' OR
                            toLower(n.path) ENDS WITH '\\\\conftest.py' OR
                            toLower(n.path) CONTAINS '/mock_' OR
                            toLower(n.path) CONTAINS '\\\\mock_'
                        )
                        RETURN n.id AS id, n.label AS label, n.kind AS kind, n.path AS path,
                               COALESCE(n.is_source, false) AS is_source
                        LIMIT $lim
                        """,
                        sid=scan_id,
                        lim=lim_nodes,
                        include_tests=include_tests,
                    )
                )
                node_ids = [r["id"] for r in nrows]
                if node_ids:
                    erows = list(
                        session.run(
                            """
                            MATCH (a:IGNode {scan_id: $sid})-[r:IG_EDGE {scan_id: $sid}]->(b:IGNode {scan_id: $sid})
                            WHERE a.id IN $node_ids AND b.id IN $node_ids
                            RETURN r.id AS id, a.id AS source, b.id AS target, r.kind AS kind,
                                   r.variable_name AS variable_name
                            LIMIT $lim
                            """,
                            sid=scan_id,
                            node_ids=node_ids,
                            lim=lim_edges,
                        )
                    )
                else:
                    erows = []
            else:
                nrows = list(
                    session.run(
                        """
                        MATCH (n:IGNode {scan_id: $sid})
                        WHERE $include_tests OR n.path IS NULL OR NOT (
                            toLower(n.path) CONTAINS '/tests/' OR
                            toLower(n.path) CONTAINS '\\\\tests\\\\' OR
                            toLower(n.path) CONTAINS '/test_' OR
                            toLower(n.path) CONTAINS '\\\\test_' OR
                            toLower(n.path) ENDS WITH '/conftest.py' OR
                            toLower(n.path) ENDS WITH '\\\\conftest.py' OR
                            toLower(n.path) CONTAINS '/mock_' OR
                            toLower(n.path) CONTAINS '\\\\mock_'
                        )
                        RETURN n.id AS id, n.label AS label, n.kind AS kind, n.path AS path,
                               COALESCE(n.is_source, false) AS is_source
                        LIMIT $lim
                        """,
                        sid=scan_id,
                        include_tests=include_tests,
                        lim=lim_nodes,
                    )
                )
                node_ids = [r["id"] for r in nrows]
                erows = list(
                    session.run(
                        """
                        MATCH (a:IGNode {scan_id: $sid})-[r:IG_EDGE {scan_id: $sid}]->(b:IGNode {scan_id: $sid})
                        WHERE a.id IN $node_ids AND b.id IN $node_ids
                        RETURN r.id AS id, a.id AS source, b.id AS target, r.kind AS kind,
                               r.variable_name AS variable_name
                        LIMIT $lim
                        """,
                        sid=scan_id,
                        node_ids=node_ids,
                        lim=lim_edges,
                    )
                )
        nrows = [r.data() for r in nrows]
        erows = [r.data() for r in erows]
        if not nrows:
            return None
        gn = [
            GraphNode(
                id=r["id"],
                label=r["label"],
                kind=r.get("kind") or "other",
                path=r.get("path") or None,
                is_source=bool(r.get("is_source")),
            )
            for r in nrows
        ]
        ge = [
            GraphEdge(
                id=r["id"],
                source=r["source"],
                target=r["target"],
                kind=r.get("kind") or "flows_to",
                variable_name=r.get("variable_name"),
            )
            for r in erows
        ]
        return TopologyPayload(nodes=gn, edges=ge)

    def delete_topology_by_scan_ids(self, scan_ids: list[str]) -> int:
        if not self._driver or not scan_ids:
            return 0
        clean_ids = [s for s in scan_ids if isinstance(s, str) and s]
        if not clean_ids:
            return 0
        with self._driver.session() as session:
            rec = session.run(
                """
                MATCH (n:IGNode)
                WHERE n.scan_id IN $scan_ids
                WITH collect(DISTINCT n) AS doomed
                UNWIND doomed AS n
                DETACH DELETE n
                RETURN size(doomed) AS deleted
                """,
                scan_ids=clean_ids,
            ).single()
            return int((rec or {}).get("deleted", 0) or 0)


_neo: Neo4jGraph | None = None


def get_neo4j() -> Neo4jGraph:
    global _neo
    if _neo is None:
        _neo = Neo4jGraph()
    return _neo
