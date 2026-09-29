/**
 * Entry point and router.
 *
 * Routing happens client-side over three paths — `/`, `/p/:id`, `/identity` — and
 * the Worker's asset handler is configured to serve the app shell for unknown
 * paths so a paste link loads the viewer directly.
 *
 * The fragment is read once here and never written into the DOM, a `history`
 * entry, an analytics call, or a fetch. There is nothing to strip afterwards
 * because it is never put anywhere.
 *
 * @module
 */
import './styles.css';
//# sourceMappingURL=main.d.ts.map