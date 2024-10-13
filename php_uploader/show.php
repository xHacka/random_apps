<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
    <link rel="stylesheet" href="assets/style.css">
    <link rel="stylesheet" href="assets/show.css">
</head>

<body>

    <div class="container">
        <h2>Uploaded Files</h2>
        <div class="table">
            <?php
            include_once "config.php";

            echo "<div class='row header'>
                    <div class='cell'>Name</div>
                    <div class='cell'>Size</div>
                    <div class='cell'>Last Modified</div>
                </div>";

            $files = scandir($UPLOAD_DIR);

            // Create an associative array with timestamps
            $filesWithTimestamps = [];
            foreach ($files as $file) {
                $filesWithTimestamps[$file] = filemtime("$UPLOAD_DIR/$file");
            }
            
            // Sort files by timestamps (latest first)
            arsort($filesWithTimestamps); // Use asort() for oldest first
            
            // Rebuild the files array based on the sorted order
            $sortedFiles = array_keys($filesWithTimestamps);

            foreach ($sortedFiles as $file) {
                if ($file === '.' || $file === '..') {
                    continue;
                }
                $filePath = "$UPLOAD_DIR/$file";

                // Check if the item is a file and not a directory
                $size = formatSize(filesize($filePath)); // Size
                $lastModified = date("Y-m-d H:i:s", filemtime($filePath)); // Last modified time

                echo "<div class='row'>
                    <div class='cell'><a href='$filePath'>$file</a></div>
                    <div class='cell'>$size</div>
                    <div class='cell'>$lastModified</div>
                </div>";
            }
            ?>
        </div>
    </div>
</body>

</html>