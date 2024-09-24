"""
This file contains the code that does the "pulling". It requests all of the files that the user
has submitted to Assemblyline for analysis via the "pusher".

The difference between this file and the results_analyzer.py is that this file is mainly about retrieving
files that are under a certain score threshold according to Assemblyline, and building a directory containing
these files.

There are 4 phases in the script, each documented accordingly.
"""

# The imports to make this thing work. All packages are default Python libraries except for the
# assemblyline_client library.
import logging
import click
import os
from time import time, sleep
from threading import Thread
from queue import Queue, Empty
import gc

from assemblyline_client import get_client
from assemblyline_client import Client4
from assemblyline_incident_manager.helper import init_logging, print_and_log, _validate_url, prepare_apikey, prepare_query_value, Client

# These are the names of the files which we will use for writing and reading information to
LOG_FILE = "directory_downloader_log.csv"

log = init_logging(LOG_FILE)

# Global
total_downloaded = 0


# These are click commands and options which allow the easy handling of command line arguments and flags
@click.group(invoke_without_command=True)
@click.option("--url", required=True, type=click.STRING, help="The target URL that hosts Assemblyline.")
@click.option("-u", "--username", required=True, type=click.STRING, help="Your Assemblyline account username.")
@click.option("--apikey", required=True, type=click.Path(exists=True, readable=True),
              help="A path to a file that contains only your Assemblyline account API key. NOTE that this API key requires read access.")
@click.option("--max_score", required=True, default=1, type=click.INT,
              help="The maximum score for files that we want to download from Assemblyline.")
@click.option("--incident_num", required=True, type=click.STRING,
              help="The incident number that each file is associated with.")
@click.option("--download_path", required=True, type=click.Path(exists=False),
              help="The path to the folder that we will download files to.")
@click.option("--upload_path", required=True, type=click.Path(exists=False),
              help="The base path from which the files were ingested from on the compromised system.")
@click.option("-t", "--is_test", is_flag=True, help="A flag that indicates that you're running a test.")
@click.option("--num_of_downloaders", default=1, type=click.INT,
              help="The number of threads that will be created to facilitate downloading the files.")
@click.option("--do_not_verify_ssl", is_flag=True, help="Verify SSL when creating and using the Assemblyline Client.")
def main(url: str, username: str, apikey: str, max_score: int, incident_num: str, download_path: str, upload_path: str,
         is_test: bool, num_of_downloaders: int, do_not_verify_ssl: bool):
    """
    Example:
    al-incident-downloader --url="https://<domain-of-Assemblyline-instance>" --username="<user-name>" --apikey="/path/to/file/containing/apikey" --incident_num=123 --min_score=100 --download_path=/path/to/where/you/want/downloads --upload_path=/path/from/where/files/were/uploaded/from
    """
    # Here is the query that we will be using to retrieve all submission details
    incident_num = prepare_query_value(incident_num)
    prepared_upload_path = prepare_query_value(upload_path)
    query = f"metadata.incident_number:\"{incident_num}\" AND max_score:<={max_score} AND metadata.filename: \"{prepared_upload_path}\""

    if is_test:
        print_and_log(log, f"INFO,The query that you will make is: {query}.", logging.DEBUG)
        # print_and_log(log, f"INFO,The files you are querying were uploaded from: {upload_path}.", logging.DEBUG)
        print_and_log(log, f"INFO,The files you are querying are to be downloaded to: {download_path}.", logging.DEBUG)
        return
    else:
        print_and_log(log, f"INFO,Query: {query}.", logging.DEBUG)
        print_and_log(log, f"INFO,Upload path: {upload_path}.", logging.DEBUG)

    # First check if the download path exists
    if not os.path.exists(download_path):
        os.mkdir(download_path)
        overwrite_all = True
        add_unique = True
    else:
        overwrite_all, add_unique = _handle_overwrite(download_path)

    if not overwrite_all and not add_unique:
        return

    # Parameter validation
    if not _validate_url(log, url):
        return

    # No trailing forward slashes in the URL!
    url = url.rstrip("/")

    apikey_val = prepare_apikey(apikey)

    # Create the Assemblyline Client
    al_client = get_client(url, apikey=(username, apikey_val), verify=not do_not_verify_ssl)
    # al_client = Client(log, url, username, apikey_val, do_not_verify_ssl).al_client

    # Create a generator that yields the SIDs for our query
    al_client.search.stream._page_size = 2000
    al_client.search.stream._max_yield_cache = 10000
    submission_res = al_client.search.stream.submission(query, fl="sid")
    # sids = []

    expected_count = al_client.search.submission(query, rows=0, track_total_hits=1_000_000_000)['total']
    print_and_log(log, f"INFO,expecting {expected_count} ids.", logging.DEBUG)

    start_time = time()

    total_already_downloaded = 0
    for _, _, files in os.walk(download_path):
        total_already_downloaded += len(files)

    file_queue: Queue[str] = Queue()
    workers = []
    unique_file_paths: set[str] = set()
    unique_file_hashes: set[str] = set()
    unrecoverable: set[str] = set()
    failed: set[str] = set()

    for _ in range(num_of_downloaders):
        # Creating a thread containing a unique AL client
        # worker_al_client = Client(log, url, username, apikey_val, do_not_verify_ssl).al_client
        # worker_al_client = get_client()

        worker = Thread(target=_thr_queue_reader,
                        args=(
                            file_queue, 
                            {"server": url, "apikey": (username, apikey_val), "verify": not do_not_verify_ssl},
                            max_score,
                            upload_path,
                            download_path,
                            overwrite_all,
                            add_unique,
                            unique_file_paths,
                            unique_file_hashes,
                            unrecoverable,
                            failed
                        ),
                        daemon=True)
        workers.append(worker)

    # Start em up!
    for worker in workers:
        worker.start()

    print_and_log(log, "INFO,Gathering the submission IDs.", logging.DEBUG)
    total_submissions_that_match_query = 0
    for submission in submission_res:
        file_queue.put(submission['sid'])
        total_submissions_that_match_query += 1

    print_and_log(log, f"INFO,There are {total_submissions_that_match_query} submission IDs.", logging.DEBUG)

    while file_queue.qsize():
        print_and_log(log, f"INFO,Waiting for the queue to empty. {file_queue.qsize()} files to process.", logging.DEBUG)
        sleep(30)

    # for _ in range(num_of_downloaders):
    #     file_queue.put("DONE")

    # Time to clock out!
    for worker in workers:
        worker.join()


    print_and_log(log, f"INFO,Download complete!", logging.INFO)
    if unrecoverable:
        print_and_log(log, f"INFO,Unrecoverable files {unrecoverable}", logging.INFO)
    if failed:
        print_and_log(log, f"INFO,Failed files {failed}", logging.INFO)

    print_and_log(
        log,
        f"INFO,{len(unique_file_paths)} unique file paths found in {total_submissions_that_match_query} submissions that match the query.",
        logging.DEBUG)
    print_and_log(
        log,
        f"INFO,{len(unique_file_hashes)} files with unique contents found in {total_submissions_that_match_query} submissions that match the query.",
        logging.DEBUG)
    print_and_log(
        log, f"INFO,{total_already_downloaded} files were downloaded to {download_path} in previous runs.", logging.DEBUG)
    print_and_log(log, f"INFO,{total_downloaded} files downloaded to {download_path} in current run.", logging.DEBUG)
    print_and_log(log, f"INFO,Total elapsed time: {time() - start_time}.", logging.DEBUG)
    print_and_log(log, "INFO,Thank you for using Assemblyline :)", logging.DEBUG)


def _handle_overwrite(download_dir: str) -> tuple[bool, bool]:
    overwrite_all = False
    add_unique = False
    overwrite = input(
        f"The download directory {download_dir} already exists. Do you wish to overwrite all contents? [y/n]:")
    if overwrite == "y":
        overwrite_all = True
    elif overwrite == "n":
        add_missing = input(
            f"The download directory {download_dir} already exists. Do you wish to download additional files to this directory? [y/n]:")
        if add_missing == "y":
            add_unique = True
        elif add_missing == "n":
            print_and_log(
                log,
                f"INFO,The download directory {download_dir} already exists. You chose not to download additional files and to exit.",
                logging.DEBUG)
        else:
            print_and_log(log, "INFO,You submitted a value that was neither [y/n]. Exiting.", logging.DEBUG)
    else:
        print_and_log(log, "INFO,You submitted a value that was neither [y/n]. Exiting.", logging.DEBUG)
    return overwrite_all, add_unique


def _thr_queue_reader(file_queue: Queue, al_client_params: dict, max_score: float, upload_path: str, download_path: str, overwrite_all, add_unique, unique_file_paths, unique_file_hashes, unrecoverable, failed) -> None:
    al_client = get_client(**al_client_params)
    global total_downloaded
    while True:
        # Try to load files to process. If no files can be found for 30 seconds we assume
        # processing is complete and exit.
        try:
            sid = file_queue.get(timeout=60)
        except Empty:
            return

        try:
            # Load the submission body
            submission = al_client.submission(sid)

            # Report failed submissions as such and take no further actions
            if submission['state'] == "failed":
                failed.add(sid)
                continue
            
            # Submissions that are still processing get delayed
            if submission['state'] == "submitted":
                print_and_log(log, f"WARNING, Waiting for ongoing submission {sid}", logging.WARN)
                sleep(0.1)
                file_queue.put(sid)
                continue

            # If the submission completes, but the score ends up being higher than the max score
            # This any condition should only contain a single item single SIDs are unique
            # if any(sub["max_score"] > max_score for sub in al_client.search.stream.submission(sid, fl="max_score")):
                # Remove the SID since it does not meet the given criteria, and move on!
                # sids.remove(sid)
                # continue
            # else:
            #     sids.remove(sid)

            # If the submission scored too high drop it and move on
            if submission['max_score'] > max_score:
                continue

            # Extract file name and hash and format it for local writing
            submitted_filepath = submission["metadata"]["filename"]
            file_hash = submission["files"][0]["sha256"]
            unique_file_paths.add(submitted_filepath)
            unique_file_hashes.add(file_hash)

            _upload_path = upload_path.strip('"')
            root_filepath = submitted_filepath.replace(_upload_path, "")
            root_filepath = root_filepath.replace("\\", os.path.sep)
            root_filepath = root_filepath.lstrip("\\")
            root_filepath = root_filepath.lstrip("/")
            filepath_to_download = os.path.normpath(os.path.join(download_path, root_filepath))

            # Make sure the directory we want to write to exists
            try:
                os.makedirs(os.path.dirname(filepath_to_download), exist_ok=True)
            except:
                print(filepath_to_download)
                print(os.path.dirname(filepath_to_download))
                print(root_filepath)
                raise

            # Check if we don't want to overwrite the file
            if not overwrite_all and add_unique:
                if os.path.exists(filepath_to_download):
                    print_and_log(
                        log,
                        f"INFO,{filepath_to_download} has already been downloaded.,{submitted_filepath},{file_hash}",
                        log_level=logging.DEBUG)
                    continue

            # Do the actual download and save
            with open(filepath_to_download, "wb") as f:
                al_client.file.download(file_hash, encoding="raw", output=f)
            print_and_log(log, f"INFO,Downloaded {filepath_to_download}", logging.DEBUG)
            total_downloaded += 1

            # Because we are cycling through a whole bunch of single use buffers
            # it playes a mess with the python garbage collector, trigger it
            # a lot more often than usual
            gc.collect()

        except Exception as exception:
            # If there was a failure due to a missing file mark it as such
            if 'The file was not found in the system.' in str(exception):
                unrecoverable.add(sid)
            else:
                # Retry on all other errors
                print_and_log(log, "ERROR, Error downloading file, will retry: " + str(exception), logging.ERROR)
                file_queue.put(sid)


if __name__ == "__main__":
    main()
