<?php
function showName() {
    global $request;
    $name = $request['get']['name'];
    echo "<p>Hello " . $name . "</p>";
}
showName();
