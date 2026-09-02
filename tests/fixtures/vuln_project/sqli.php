<?php
function lookupUser() {
    global $request;
    $id = $request['get']['id'];
    $mysqli = new mysqli('localhost', 'user', 'pass', 'db');
    $mysqli->query("SELECT * FROM users WHERE id = " . $id);
}
lookupUser();
