// Ground-truth runner: applies setup + migration to a real PostgreSQL (PGlite = PostgreSQL compiled to WASM)
// and reports which consumer queries fail afterwards.  stdin: {setup:[], migration:[], queries:{id:sql}}
import { PGlite } from "@electric-sql/pglite";
let raw = "";
for await (const c of process.stdin) raw += c;
const spec = JSON.parse(raw);
const db = new PGlite();
const out = { migration_error: null, query_errors: {}, query_ok: [] };
for (const s of spec.setup || []) await db.exec(s);
for (const q of Object.entries(spec.pre_queries || {})) {
  try { await db.exec("BEGIN"); await db.query(q[1]); } catch (e) { out.query_errors["PRE:" + q[0]] = e.message; } finally { await db.exec("ROLLBACK"); }
}
try {
  await db.exec("BEGIN");
  for (const s of spec.migration || []) await db.exec(s);
  await db.exec("COMMIT");
} catch (e) { out.migration_error = e.message; try { await db.exec("ROLLBACK"); } catch {} }
if (!out.migration_error) {
  for (const [id, sql] of Object.entries(spec.queries || {})) {
    try { await db.exec("BEGIN"); await db.query(sql); out.query_ok.push(id); }
    catch (e) { out.query_errors[id] = e.message; }
    finally { try { await db.exec("ROLLBACK"); } catch {} }
  }
}
console.log(JSON.stringify(out));
