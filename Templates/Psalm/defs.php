<?php

class HTMLPurifier {
    /**
     * @psalm-flow ($html) -> return
     */
    public function purify(string $html, $config = null): string {}
}

/**
 * @psalm-taint-source input
 */
function file_get_contents(string $filename, bool $use_include_path = false, $context = null, int $offset = 0, ?int $length = null): string|false {}