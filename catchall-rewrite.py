import argparse
import base64
import binascii
import email
import email.headerregistry
import email.policy
import enum
import os
import sys

from opensmtpd import FilterServer

class MessageHandlerAction(enum.Enum):
    # Do nothing
    PASS = 1
    # Modify the inbound message (rewrite the reply-to header or add it)
    MODIFY_INBOUND = 2
    # Modify the outbound message (rewrite the from, to, and reply-to headers)
    MODIFY_OUTBOUND = 3

catchall_recipient_map = dict()
stderr = os.fdopen(sys.stderr.fileno(), 'w', encoding='latin-1', buffering=1)

def debug_msg(msg):
    print(msg, file=stderr)

def read_recipient_map(map_file):
    try:
        map_information = open(map_file, 'r')
    except OSError:
        # If we cannot read the file or there is some other issue, the
        # recipient map will not be populated, and this filter will not do anything
        return
    else:
        with map_information:
            for line in map_information.readlines():
                try:
                    # Lines in OpenSMTPd alias files have the format [key]<whitespace>[value]
                    (catchall_recipient, local_recipient) = line.split()
                    catchall_recipient_map[catchall_recipient] = local_recipient
                    debug_msg(f'Mapped recipient {catchall_recipient} to {local_recipient}')
                except ValueError:
                    continue

def extract_recipient(session, message_id, result, address):
    """Stores the receipient of the current message in the session."""
    if result != 'ok':
        return
    if not address.endswith('@catchall.invalid') or address not in catchall_recipient_map:
        debug_msg(f'Catchall not processing message for {address}')
        session['action'] = MessageHandlerAction.PASS
        return
    
    if address.endswith('@catchall.invalid'):
        debug_msg(f'Received outbound mail for catchall: {address}')
        catchall_information = address[:address.rindex('@catchall.invalid')]
        try:
            catchall_information_decoded = base64.b64decode(catchall_information).decode()
        except (binascii.Error, UnicodeDecodeError):
            session['action'] = MessageHandlerAction.PASS
            return

        catchall_reply_information = catchall_information_decoded.split(b'\x1e')
        if len(catchall_reply_information) != 4:
            # We encoded 4 elements, so we expect 4 elements back
            session['action'] = MessageHandlerAction.PASS
            return
        
        try:
            (outbound_catchall_addr, outbound_recipient_display_name, outbound_recipient_username, outbound_recipient_domain) = (part.decode('utf-8') for part in catchall_reply_information)
            debug_msg(f'Catchall information: FROM: {outbound_catchall_addr}; DISP: {outbound_recipient_display_name}; TO: {outbound_recipient_username}@{outbound_recipient_domain}')
            (outbound_catchall_user, outbound_catchall_domain) = outbound_catchall_addr.split('@')
        except ValueError:
            # What will happen will happen
            session['action'] = MessageHandlerAction.PASS
            return
        
        session['outbound_recipient'] = email.headerregistry.Address(display_name=outbound_recipient_display_name, username=outbound_recipient_username, domain=outbound_recipient_domain)
        session['outbound_sender'] = email.headerregistry.Address(display_name='', username=outbound_catchall_user, domain=outbound_catchall_domain)
        session['action'] = MessageHandlerAction.MODIFY_OUTBOUND
    else:
        debug_msg(f'Received message for catchall recipient {address} (mapped to {catchall_recipient_map.get("address")})')
        session['catchall_recipient'] = address
        session['local_recipient'] = catchall_recipient_map.get('address')
        session['action'] = MessageHandlerAction.MODIFY_INBOUND

def modify_inbound_recipients(session, lines):
    local_recipient = session.get('local_recipient')
    catchall_recipient = session.get('catchall_recipient')
    if local_recipient is None or catchall_recipient is None:
        return lines
    
    
    # The default email policy, email.policy.default, parses the entire message as opposed to
    # the compat32 policy which only parses the header and is used by default
    parsed_message = email.message_from_string('\n'.join(lines), policy=email.policy.default)

    # The email parser takes care of different capitalizations of headers
    # Will base64 the parts that we need (catch all address that is receiving the message, and display name, username, and domain of the external correspondant)
    # Each part will be separated by \x1e (record separator) which is not printable and should not occur in a valid email address
    # We have to use something non-printable as opposed to whitespace because the display name can include whitespace
    # .invalid is a reserved TLD so we will use that to denote an address where we need to take action later
    if 'reply-to' in parsed_message:
        # According to RFC2822, there should only be one reply-to address if it exists,
        # so we will only work on the first one we find
        original_reply_to = parsed_message['reply-to'].address
        catchall_reply_to = b'\x1e'.join([catchall_recipient.encode(), original_reply_to.display_name.encode(), original_reply_to.username.encode(), original_reply_to.domain.encode()])
        debug_msg(f'Rewriting reply to address from {original_reply_to} to {base64.b64encode(catchall_reply_to).decode("utf-8")}')
        new_reply_to = email.headerregistry.Address(display_name='', username=base64.b64encode(catchall_reply_to).decode('utf-8'), domain='catchall.invalid')
        parsed_message.replace_header('reply-to', new_reply_to)
    else:
        original_from = parsed_message['from'].address
        catchall_reply_to = b'\x1e'.join([catchall_recipient.encode(), original_from.display_name.encode(), original_from.username.encode(), original_from.domain.encode()])
        catchall_reply_to_b64 = base64.b64encode(catchall_reply_to).decode('utf-8')
        debug_msg(f'Adding reply-to address {catchall_reply_to_b64}@catchall.invalid to message')
        parsed_message.add_header('reply-to', f'{catchall_reply_to_b64}@catchall.invalid')
    
    # Return the edited message
    return parsed_message.as_string().strip().split('\n')

def modify_outbound_recipients(session, lines):
    catchall_sender = session.get('outbound_sender')
    true_recipient = session.get('outbound_recipient')

    if catchall_sender is None or true_recipient is None:
        return lines
    
    parsed_message = email.message_from_string('\n'.join(lines), policy=email.policy.default)
    # From must exist according to the RFC
    parsed_message.replace_header('from', catchall_sender)

    if 'reply-to' in parsed_message:
        parsed_message.replace_header('reply-to', catchall_sender)
    else:
        parsed_message.add_header('reply-to', str(catchall_sender))
    
    # To must exist according to the RFC
    parsed_message.replace_header('to', true_recipient)

    debug_msg(f'OUTBOUND: Rewrote addresses. To: {true_recipient}, From: {catchall_sender}, Reply-to: {catchall_sender}')

    return parsed_message.as_string().strip().split('\n')

def rewrite_message_recipients(session, lines):
    """Adds the appropriate Reply To: header to inbound emails and modifies the receipient to the appropriate recipient based on the recipient table."""
    action = session.get('action')
    if action is None or action == MessageHandlerAction.PASS:
        return lines
    elif action == MessageHandlerAction.MODIFY_INBOUND:
        return modify_inbound_recipients(session, lines)
    else:
        return modify_outbound_recipients(session, lines)


def start():
    argument_parser = argparse.ArgumentParser(description='Catchall domain rewriter for OpenSMTPd')
    argument_parser.add_argument('file', help='Path to the recipient table containing a mapping of catch all addresses to recipients')
    arguments = argument_parser.parse_args()
    read_recipient_map(arguments.file)

    server = FilterServer()
    # Set up sessions that we can use to track senders and recipients
    # for the duration of the session
    server.track_context()

    # Register a handler for the 'tx-rcpt' event which parses out the recipient
    server.register_handler('report', 'tx-rcpt', extract_recipient)

    # Register the rewrite_message_recipients filter
    server.register_message_filter(lambda session, lines: rewrite_message_recipients(session, lines))

    # Go!
    server.serve_forever()

if __name__ == 'main':
    start()
