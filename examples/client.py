"""
    Client to connect to server and register a device
"""
import dataclasses
import requests

from unittest import mock
from fido2 import cbor
from fido2.utils import sha256, websafe_encode, _snake2camel
from fido2.hid import CAPABILITY
from fido2.ctap import CtapError
from fido2.ctap1 import RegistrationData
from fido2.ctap2 import Info, AttestationResponse
from fido2.client import ClientError, Fido2Client
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    CredentialCreationOptions,
    AttestationObject,
    CollectedClientData,
    RegistrationResponse,
    AuthenticatorData
)

import fido2.features

fido2.features.webauthn_json_mapping.enabled = True

APP_ID = "http://localhost:5000"

REG_DATA = RegistrationData(
    bytes.fromhex(
        "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871"  # noqa E501
    )
)

rp = {"id": "localhost", "name": "Example RP"}
user = {"id": bytes("user_id", encoding='ascii'), "name": "A. User"}
challenge = b"Y2hhbGxlbmdl"
_INFO_NO_PIN = bytes.fromhex(
    "a60182665532465f5632684649444f5f325f3002826375766d6b686d61632d7365637265740350f8a011f38c0a4d15800617111f9edc7d04a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b0068101"  # noqa E501
)
_MC_RESP = bytes.fromhex(
    "a301667061636b6564025900c40021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12410000001cf8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a529003a363616c67266373696758483046022100cc1ef43edf07de8f208c21619c78a565ddcf4150766ad58781193be8e0a742ed022100f1ed7c7243e45b7d8e5bda6b1abf10af7391789d1ef21b70bd69fed48dba4cb163783563815901973082019330820138a003020102020900859b726cb24b4c29300a06082a8648ce3d0403023047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e301e170d3136313230343131353530305a170d3236313230323131353530305a3047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3059301306072a8648ce3d020106082a8648ce3d03010703420004ad11eb0e8852e53ad5dfed86b41e6134a18ec4e1af8f221a3c7d6e636c80ea13c3d504ff2e76211bb44525b196c44cb4849979cf6f896ecd2bb860de1bf4376ba30d300b30090603551d1304023000300a06082a8648ce3d0403020349003046022100e9a39f1b03197525f7373e10ce77e78021731b94d0c03f3fda1fd22db3d030e7022100c4faec3445a820cf43129cdb00aabefd9ae2d874f9c5d343cb2f113da23723f3"  # noqa E501
)

@mock.patch("fido2.client.Ctap2")
def make_client(PatchedCtap2):
    # Make a device 
    dev = mock.Mock()
    dev.capabilities = CAPABILITY.CBOR
    ctap2 = mock.MagicMock()
    ctap2.get_info.return_value = Info.from_dict(cbor.decode(_INFO_NO_PIN))
    ctap2.info = ctap2.get_info()
    ctap2.make_credential.return_value = AttestationResponse.from_dict(
        cbor.decode(_MC_RESP)
    )
    PatchedCtap2.return_value = ctap2

    # Make client
    client = Fido2Client(dev, APP_ID)

    return client

if __name__ == "__main__":

    # Hit register begin endpoint

    resp = requests.post('http://localhost:5000/api/register/begin')
    print("resp", resp)
    print("resp cookies", resp.cookies)
    cookies = resp.cookies
    print("resp headers", resp.headers)
    headers = resp.headers
    print("resp json", resp.json())
    print("====================================")

    client = make_client()
    # resp.json()['publicKey']
    # response = client.make_credential(
    #     PublicKeyCredentialCreationOptions(
    #         rp,
    #         user,
    #         challenge,
    #         [{"type": "public-key", "alg": -7}],
    #         timeout=1000,
    #         authenticator_selection={"userVerification": "discouraged"},
    #     )
    # )
    options = CredentialCreationOptions.from_dict(resp.json()).public_key
    reg_response = client.make_credential(options)

    print(f"{reg_response=}")
    print("====================================")

    # reg_response.attestation_object.auth_data.rp_id_hash = options.rp.id_hash 

    # ad = ao["authData"]
    ad = reg_response.attestation_object.auth_data
    new_ad = AuthenticatorData.create(b'I\x96\r\xe5\x88\x0e\x8cht4\x17\x0fdv`[\x8f\xe4\xae\xb9\xa2\x862\xc7\x99\\\xf3\xba\x83\x1d\x97c', ad.flags, ad.counter, ad.credential_data, ad.extensions)
    ao = {_snake2camel(k): v if k != "auth_data" else new_ad for k,v in reg_response.attestation_object.__dict__.items()}
    # body = {"clientData": response.client_data.decode().encode(), "attestationObject": cbor.encode(ao)}
    body = {"id": websafe_encode(b'1'), "response": {"clientDataJSON": reg_response.client_data.b64, "attestationObject": websafe_encode(cbor.encode(ao))}}
    # body = {"id": websafe_encode(b'1'), "eesponse": {"client_data": response.client_data.decode(), "attestation_object": cbor.encode(ao).__str__()}}
    # body = {"id": websafe_encode(b'1'), "response": response}
    # Hit register complete endpoint
    resp2 = requests.post(
        'http://localhost:5000/api/register/complete',
        json=body,
        headers=headers,
        cookies=cookies
    )
    print("resp2", resp2)
    print("resp2 cookies", resp2.cookies)
    print("resp2 headers", resp2.headers)
    print("resp2 json", resp2.json())
    print("====================================")

