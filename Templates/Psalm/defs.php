<?php
/**
 * @psalm-taint-source input
 */
function file_get_contents(string $filename, bool $use_include_path = false, $context = null, int $offset = 0, ?int $length = null): string|false {}

class mysqli_ext extends mysqli {
    /**
     * @psalm-taint-sink sql $query
     */
    public function query(string $query, int $result_mode = MYSQLI_STORE_RESULT): mysqli_result|bool {}
}