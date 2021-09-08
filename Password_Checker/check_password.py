import requests
import hashlib
import sys


def request_api_data(query):
    url = f'https://api.pwnedpasswords.com/range/{query}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error {res.status_code}! Please check the API and try again. ')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def check_pwnd_api(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha1_first_5_char, sha1_tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(sha1_first_5_char)
    return get_password_leaks_count(response, sha1_tail)


def main(args):
    for password in args:
        count = check_pwnd_api(password)
        if count:
            print(
                f'{password} was found {count} times... You should probably change your password.')
        else:
            print(f'{password} was not found. Phew!')
    return 'Password check complete!'


if __name__ == '__main__':
    # sys.exit(main(['']))
    sys.exit(main(sys.argv[1:]))
