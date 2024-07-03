<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "bookstoretest1";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$sql = "SELECT BookTitle FROM featuredbooks LIMIT 1";
$result = $conn->query($sql);

$bookTitle = "";

if ($result->num_rows > 0) {
    // Fetch the first row
    $row = $result->fetch_assoc();
    $bookTitle = $row['BookTitle'];
}
$conn->close();

echo json_encode($bookTitle);
?>