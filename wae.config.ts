/**
 * Build and release configuration for OpenIDA.
 *
 * Pure literals only: `wae` parses this file statically and never executes it.
 * Build order is fixed: native → ts → ui → skills → staging.
 *
 * The packages live under `projects/packages`; the native addon is built from
 * the `open-ida-napi` crate and staged into the per-platform packages.
 */
import { defineConfig } from '@wae/wae';

export default defineConfig({
    native: {
        crate: 'open-ida-napi',
        cdylib: 'open_ida_napi',
        targets: [
            {
                platform: 'win32',
                arch: 'x64',
                triple: 'x86_64-pc-windows-msvc',
                package: '@wae/open-ida-win32-x64',
                nodeFile: 'open-ida.win32-x64.node',
                dir: 'projects/packages/open-ida-win32-x64',
            },
            {
                platform: 'darwin',
                arch: 'x64',
                triple: 'x86_64-apple-darwin',
                package: '@wae/open-ida-darwin-x64',
                nodeFile: 'open-ida.darwin-x64.node',
                dir: 'projects/packages/open-ida-darwin-x64',
            },
            {
                platform: 'darwin',
                arch: 'arm64',
                triple: 'aarch64-apple-darwin',
                package: '@wae/open-ida-darwin-arm64',
                nodeFile: 'open-ida.darwin-arm64.node',
                dir: 'projects/packages/open-ida-darwin-arm64',
            },
            {
                platform: 'linux',
                arch: 'x64',
                triple: 'x86_64-unknown-linux-gnu',
                package: '@wae/open-ida-linux-x64',
                nodeFile: 'open-ida.linux-x64.node',
                dir: 'projects/packages/open-ida-linux-x64',
            },
            {
                platform: 'linux',
                arch: 'arm64',
                triple: 'aarch64-unknown-linux-gnu',
                package: '@wae/open-ida-linux-arm64',
                nodeFile: 'open-ida.linux-arm64.node',
                dir: 'projects/packages/open-ida-linux-arm64',
            },
        ],
    },
    packages: [
        {
            name: '@wae/open-ida-win32-x64',
            dir: 'projects/packages/open-ida-win32-x64',
            os: ['win32'],
            cpu: ['x64'],
            main: 'open-ida.win32-x64.node',
        },
        {
            name: '@wae/open-ida-darwin-x64',
            dir: 'projects/packages/open-ida-darwin-x64',
            os: ['darwin'],
            cpu: ['x64'],
            main: 'open-ida.darwin-x64.node',
        },
        {
            name: '@wae/open-ida-darwin-arm64',
            dir: 'projects/packages/open-ida-darwin-arm64',
            os: ['darwin'],
            cpu: ['arm64'],
            main: 'open-ida.darwin-arm64.node',
        },
        {
            name: '@wae/open-ida-linux-x64',
            dir: 'projects/packages/open-ida-linux-x64',
            os: ['linux'],
            cpu: ['x64'],
            main: 'open-ida.linux-x64.node',
        },
        {
            name: '@wae/open-ida-linux-arm64',
            dir: 'projects/packages/open-ida-linux-arm64',
            os: ['linux'],
            cpu: ['arm64'],
            main: 'open-ida.linux-arm64.node',
        },
    ],
    build: {
        ts: { packages: ['@wae/open-ida'] },
        ui: { package: '@wae/open-ida-ui' },
        stage: [
            {
                from: 'projects/packages/open-ida-ui/dist/static',
                to: 'projects/packages/open-ida/dist/gui',
                clean: true,
            },
        ],
        outputs: [
            'projects/packages/open-ida/dist/cli.js',
            'projects/packages/open-ida/dist/gui/index.html',
        ],
    },
    skills: {
        packages: [
            {
                dir: 'projects/packages/open-ida-skills/skills',
                packageJson: 'projects/packages/open-ida-skills/package.json',
                appPackageJson: 'projects/packages/open-ida/package.json',
                cliEntry: 'projects/packages/open-ida/dist/cli.js',
                commandName: 'open-ida',
            },
        ],
    },
    // `release` is intentionally unset while the app packages stay `private`;
    // the platform packages are the only publishable set and have no CI release
    // workflow yet.
    ci: {
        repo: 'nyar-os/OpenIDA',
        workflows: ['check-rust.yml', 'check-typescript.yml'],
        requiredJobs: ['build', 'check'],
        shaBinding: false,
    },
    install: { shortcutDefault: true },
    audit: { actor: { kind: 'flag', id: 'flag', source: 'flag' } },
    window: { mode: 'single', secondLaunch: 'focus' },
});
