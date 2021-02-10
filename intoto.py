import binascii
import dnf.cli
import dnf.exceptions
import dnf.subject
import dnf.package
import logging
import os
import requests
import shutil
import tempfile

import in_toto.exceptions
import in_toto.verifylib
import in_toto.models.link
import in_toto.models.metadata
import securesystemslib.gpg.functions

from dnf.i18n import _
from dnf.cli.option_parser import OptionParser

logger = logging.getLogger('dnf')

PLUGIN_CONF = 'intoto'


def _intoto_verify(global_info, pkg):
    logger.info("Prepare in-toto verification for '{}'".format(pkg))

    # Create temp dir
    verification_dir = tempfile.mkdtemp()
    logger.info("Create verification directory '{}'".format(verification_dir))

    logger.info("Request in-toto metadata from {} rebuilder(s) (DNF global_info)".format(len(global_info["config"]["Rebuilders"])))
    # Download link files to verification directory
    for rebuilder in global_info["config"]["Rebuilders"]:
        # Accept rebuilders with and without trailing slash
        verrel = "{}-{}".format(pkg.version, pkg.release)
        endpoint = "{rebuilder}/sources/{name}/{verrel}/metadata".format(rebuilder=rebuilder.rstrip("/"), name=pkg.source_name, verrel=verrel)

        logger.info("Request in-toto metadata from {}".format(endpoint))
        try:
            # Fetch metadata
            response = requests.get(endpoint)
            if not response.status_code == 200:
                raise Exception("server response: {}".format(response.status_code))

            # Decode json
            link_json = response.json()

            # Load as in-toto metadata
            link_metablock = in_toto.models.metadata.Metablock(
                signatures=link_json["signatures"],
                signed=in_toto.models.link.Link.read(link_json["signed"]))

            # Construct link name as required by in-toto verification
            link_name = in_toto.models.link.FILENAME_FORMAT.format(
                keyid=link_metablock.signatures[0]["keyid"],
                step_name=link_metablock.signed.name)

            # Write link metadata to temporary verification directory
            link_metablock.dump(os.path.join(verification_dir, link_name))
        except Exception as e:
            # We don't fail just yet if metadata cannot be downloaded or stored
            # successfully. Instead we let in-toto verification further below fail if
            # there is not enought metadata
            logger.warning("Could not retrieve in-toto metadata from rebuilder '{}', reason was: {}".format(rebuilder, e))
            continue
        else:
            logger.info("Successfully downloaded in-toto metadata '{}' from rebuilder '{}'".format(link_name, rebuilder))

    logger.info("Copy final product to verification directory")

    # Temporarily change to verification, changing back afterwards
    cached_cwd = os.getcwd()
    os.chdir(verification_dir)

    try:
        logger.info("Load in-toto layout '{}' (DNF global_info)".format(global_info["config"]["Layout"]))

        layout = in_toto.models.metadata.Metablock.load(global_info["config"]["Layout"])
        keyids = global_info["config"]["Keyids"]
        gpg_home = global_info["config"]["GPGHomedir"]

        logger.info("Load in-toto layout key(s) '{}' (DNF global_info)".format(global_info["config"]["Keyids"]))
        if gpg_home:
            logger.info("Use gpg keyring '{}' (DNF global_info)".format(gpg_home))
            layout_keys = securesystemslib.gpg.functions.export_pubkeys(keyids, homedir=gpg_home)
        else:
            logger.info("Use default gpg keyring")
            layout_keys = securesystemslib.gpg.functions.export_pubkeys(keyids)

        logger.info("Run in-toto verification")
        chksum_type, chksum_value = pkg.chksum
        prerecorded_inspections = {
            "rebuild": {
                "products": {
                    os.path.basename(pkg.remote_location()): binascii.hexlify(chksum_value).decode('utf-8')
                }
            }
        }
        in_toto.verifylib.in_toto_verify(layout, layout_keys, prerecorded_inspections=prerecorded_inspections)
    except Exception as e:
        error_msg = ("In-toto verification for '{}' failed, reason was: {}".format(pkg, str(e)))
        if isinstance(e, in_toto.exceptions.LinkNotFoundError) and global_info["config"].get("NoFail"):
            logger.error(error_msg)
            logger.warning("The 'NoFail' setting is enabled, installation continues.")
        else:
            raise dnf.exceptions.Error(error_msg)
    else:
        logger.info("In-toto verification for '{}' passed! :)".format(pkg))
    finally:
        os.chdir(cached_cwd)
        shutil.rmtree(verification_dir)


class InTotoCommand(dnf.cli.Command):
    """DNF in-toto cli command."""

    aliases = ['intoto']

    def configure(self):
        self.cli.demands.available_repos = True
        self.cli.demands.sack_activation = True
        self.cli.demands.fresh_metadata = True

    @staticmethod
    def set_argparser(parser):
        parser.add_argument('package', nargs='+', metavar=_('PACKAGE'),
                            action=OptionParser.ParseSpecGroupFileCallback,
                            help=_('Package to verify in-toto metadata'))

    def run(self):
        """Run the command."""
        pass


class InTotoPlugin(dnf.Plugin):
    """DNF in-toto plugin."""
    name = 'intoto'

    def __init__(self, base, cli):
        super(InTotoPlugin, self).__init__(base, cli)
        # TODO: cli command
        # if cli:
        #     cli.register_command(InTotoCommand)

    def resolved(self):
        config = self.read_config(self.base.conf)
        if config.getboolean('main', 'enabled'):
            for key in ["rebuilders", "gpghomedir", "layout", "keyids", "nofail"]:
                if not config.hasOption("main", key):
                    raise dnf.exceptions.Error("in-toto: missing config value for '%s'" % key)
            global_info = {
                "config": {
                    "Rebuilders": config.getValue("main", "rebuilders").split(),
                    "GPGHomedir": config.getValue("main", "gpghomedir"),
                    "Layout": config.getValue("main", "layout"),
                    "Keyids": config.getValue("main", "keyids").split(),
                    "NoFail": config.getboolean("main", "nofail"),
                    "OnlyRepos": config.getValue("main", "onlyrepos").split(),
                }
            }
            for item in self.base.transaction:
                filtered_repos = global_info["config"]["OnlyRepos"]
                if not filtered_repos or item.pkg.reponame in filtered_repos:
                    _intoto_verify(global_info, item.pkg)
                else:
                    logger.info("Skipping in-toto verification for '{}' due to repository filtering".format(item.pkg))
