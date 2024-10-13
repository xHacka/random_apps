<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <h1>File Upload System</h1>
        
        <div id="upload-area" class="upload-area">
            <h2>Drag and Drop Upload</h2>
            <p>Drag and drop files here or click to upload</p>
            <input type="file" id="file-input" multiple hidden>
            <div id="file-drop-area">Drop files here...</div>
        </div>
        
        <div class="upload-manual">
            <h2>Paste Your Text Here</h2>
            <form id="manual-upload" action="upload.php" method="POST" enctype="multipart/form-data">
                <textarea name="contents" rows="10" placeholder="Paste your text here..." required></textarea>
                <input type="text" name="filename" placeholder="Enter custom name (Optional)">
                <button type="submit">Upload</button>
            </form>
        </div>


    </div>

    <script>
        document.getElementById('file-drop-area').addEventListener('click', function() { document.getElementById('file-input').click(); });
        document.getElementById('file-input').addEventListener('change', function(event) { uploadFiles(event.target.files); });
        document.getElementById('file-drop-area').addEventListener('dragover', function(event) { event.preventDefault(); });
        document.getElementById('file-drop-area').addEventListener('drop', function(event) { event.preventDefault(); uploadFiles(event.dataTransfer.files); });

        function uploadFiles(files) {
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) { formData.append('files[]', files[i]); }
            fetch('upload.php', { method: 'POST', body: formData })
            .then(response => response.text())
            .then(data => { alert(data); location.reload(); })
            .catch(error => { console.error('Error:', error); });
        }

        document.getElementById('manual-upload').addEventListener('submit', function(event) {
            event.preventDefault();
            const formdata = new FormData(this);
            console.log(...formdata)
            fetch('upload.php', { method: 'POST', body: formdata })
            .then(response => response.text())
            .then(data => { alert(data); location.reload(); })
            .catch(error => { console.error('Error:', error); });
        });
    </script>
</body>
</html>
