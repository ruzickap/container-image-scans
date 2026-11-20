<script lang="ts">
  import { tick } from 'svelte'
  import { query, type Cve, type Scan } from './lib/dynamodb'

  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

  let status = $state('Loading ...')
  let scans = $state<Scan[]>([])
  let selected = $state<Scan>()
  let cves = $state<Cve[]>([])
  let section = $state<HTMLElement>()
  // Only the last clicked scan is shown - a slower answer to an earlier click is dropped
  let lastClick = 0

  function showError (error: unknown) {
    status = `Error: ${error instanceof Error ? error.message : String(error)}`
  }

  // Links only to https URLs - the URL comes from the scanner data
  function isHttps (url: string | undefined): boolean {
    return url?.startsWith('https://') ?? false
  }

  async function loadScans () {
    const items = await query<Scan>('LATEST')
    items.sort(
      (a, b) =>
        a.group.localeCompare(b.group) ||
        a.vendor.localeCompare(b.vendor) ||
        a.scanner.localeCompare(b.scanner)
    )
    scans = items
    status = items.length ? '' : 'No scans yet.'
  }

  async function showCves (scan: Scan) {
    const click = ++lastClick
    status = `Loading CVEs of ${scan.image} (${scan.scanner}) ...`
    let items: Cve[]
    try {
      items = await query<Cve>(scan.cves_pk)
    } catch (error) {
      // An error of an earlier click must not replace the last click result
      if (click === lastClick) {
        showError(error)
      }
      return
    }
    if (click !== lastClick) {
      return
    }
    items.sort(
      (a, b) =>
        SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
        a.sk.localeCompare(b.sk)
    )
    selected = scan
    cves = items
    status = ''
    await tick()
    section?.scrollIntoView()
  }

  loadScans().catch(showError)
</script>

<h1>Container Image Scans</h1>
<p>
  CVEs found by trivy and grype in the latest scan. Select an image to see its
  CVEs.
</p>
<p role="status">{status}</p>

{#if scans.length}
  <table>
    <thead>
      <tr>
        <th>Group</th>
        <th>Vendor</th>
        <th>Image</th>
        <th>Scanner</th>
        <th>Critical</th>
        <th>High</th>
        <th>Medium</th>
        <th>Low</th>
        <th>Total</th>
        <th>Scanned (UTC)</th>
      </tr>
    </thead>
    <tbody>
      {#each scans as scan (scan.sk)}
        <tr>
          <td title={scan.group_description}>{scan.group}</td>
          <td>{scan.vendor}</td>
          <td>
            <button type="button" onclick={() => showCves(scan).catch(showError)}>
              {scan.image}
            </button>
            <br />
            <small>{scan.image_description}</small>
          </td>
          <td>{scan.scanner}</td>
          <td>{scan.cve_critical}</td>
          <td>{scan.cve_high}</td>
          <td>{scan.cve_medium}</td>
          <td>{scan.cve_low}</td>
          <td>{scan.cve_total}</td>
          <td>{scan.scanned_at}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if selected}
  <section bind:this={section}>
    <h2>
      {selected.group} / {selected.vendor}: {selected.image} - {selected.scanner}
      ({selected.scanned_at})
    </h2>
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>Severity</th>
          <th>Package</th>
          <th>Installed</th>
          <th>Fixed</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {#each cves as cve (cve.sk)}
          <tr>
            <td>
              {#if isHttps(cve.url)}
                <a href={cve.url} rel="noopener noreferrer">{cve.cve_id}</a>
              {:else}
                {cve.cve_id}
              {/if}
            </td>
            <td>{cve.severity}</td>
            <td>{cve.package_name}</td>
            <td>{cve.installed_version}</td>
            <td>{cve.fixed_version}</td>
            <td>{cve.description}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
{/if}
