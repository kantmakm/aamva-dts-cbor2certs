import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os # Added for path handling

# 1. Define the target URL and output filename
BASE_URL = "https://vical.dts.aamva.org/"
TARGET_FILENAME = "vical.zip" 

# 2. Fetch the HTML content
try:
    response = requests.get(BASE_URL)
    response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
except requests.exceptions.RequestException as e:
    print(f"Error fetching the page: {e}")
    exit()

# 3. Parse the HTML and Locate the Target Link
soup = BeautifulSoup(response.content, 'html.parser')

# A. Find the table with id="currentvical"
current_vical_table = soup.find('table', id='currentvical')

if not current_vical_table:
    print("❌ Error: Could not find the HTML table with id='currentvical'.")
    exit()

# B. Within that table, find the first <a> tag with class="btn btn-primary"
# Using a dictionary for class search ensures exact matching of the classes.
download_link_tag = current_vical_table.find('a', class_='btn btn-primary')

if not download_link_tag:
    print("❌ Error: Could not find an <a> tag with class='btn btn-primary' inside the table.")
    exit()

# 4. Extract the full download URL
relative_url = download_link_tag.get('href')
if not relative_url:
    print("❌ Error: The found link tag does not have an 'href' attribute.")
    exit()
    
full_download_url = urljoin(BASE_URL, relative_url)

print(f"✅ Found Current VICAL URL: {full_download_url}")

# --- 5. Download the File ---

# It's good practice to derive the filename from the URL if possible, 
# but we stick to the hardcoded name for consistency.
try:
    print(f"Starting download to {TARGET_FILENAME}...")
    # Use stream=True for potentially large files
    file_response = requests.get(full_download_url, stream=True)
    file_response.raise_for_status()

    # Save the content to a file
    with open(TARGET_FILENAME, 'wb') as f:
        # Write the file in chunks
        for chunk in file_response.iter_content(chunk_size=8192):
            f.write(chunk)

    print(f"🎉 Successfully downloaded Current VICAL to: {os.path.abspath(TARGET_FILENAME)}")

except requests.exceptions.RequestException as e:
    print(f"❌ Error downloading the file: {e}")
