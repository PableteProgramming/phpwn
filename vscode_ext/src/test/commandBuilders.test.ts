import * as assert from 'assert';
import {
    pythonExecutableName,
    buildVenvCommand,
    buildConfigureCommand,
    buildRunCommand
} from '../commandBuilders';

suite('commandBuilders', () => {
    test('uses python3 on non-Windows platforms', () => {
        assert.strictEqual(pythonExecutableName('linux'), 'python3');
        assert.strictEqual(pythonExecutableName('darwin'), 'python3');
    });

    test('uses python on Windows', () => {
        assert.strictEqual(pythonExecutableName('win32'), 'python');
    });

    test('venv command matches the platform\'s python executable', () => {
        assert.strictEqual(buildVenvCommand('win32'), 'python -m venv .venv');
        assert.strictEqual(buildVenvCommand('linux'), 'python3 -m venv .venv');
    });

    test('quotes a workspace path containing spaces (configure)', () => {
        assert.strictEqual(
            buildConfigureCommand('/venv/bin/python3', 'My Project'),
            '"/venv/bin/python3" PHPwn.py --configure "My Project"'
        );
    });

    test('quotes a workspace path containing spaces (run)', () => {
        assert.strictEqual(
            buildRunCommand('/venv/bin/python3', 'My Project'),
            '"/venv/bin/python3" PHPwn.py "My Project"'
        );
    });
});
