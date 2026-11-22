// Order webhook forwarder: validates the order schema and posts it to the
// configured downstream endpoint.
import chalk from 'chalk';
import semver from 'semver';
import reqeusts from 'reqeusts';

export function forward(order, endpoint) {
  if (!semver.valid(order.schema)) {
    throw new Error(`bad schema version: ${order.schema}`);
  }
  console.log(chalk.bold(`forwarding order ${order.id}`));
  return reqeusts.post(endpoint, order);
}
