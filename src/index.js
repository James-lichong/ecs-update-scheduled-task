const aws = require('aws-sdk');
const core = require('@actions/core');
const ecsCwe = require('./ecs-cwe');
const fs = require('fs');
const path = require('path');
const yaml = require('yaml');

/*
 * Target object for example:
 * {
 *   Id: 'Alpine-Cron-Demo-Scheduled-Task',
 *   Arn: 'arn:aws:ecs:<REGION>:<ACCOUNT ID>:cluster/<CLUSTER NAME>',
 *   RoleArn: 'arn:aws:iam::<ACCOUNT ID>:role/ecsEventsRole',
 *   Input: '{"containerOverrides":[{"name":"Alpine-Demo","command":["sleep"," 50"]}]}',
 *   EcsParameters: {
 *     TaskDefinitionArn:
 *     'arn:aws:ecs:<REGION>:<ACCOUNT ID>:task-definition/Alpine-Cron-Demo:<VERSION>',
 *     TaskCount: 1,
 *     LaunchType: 'EC2'
 *   }
 * }
 */

async function processCloudwatchEventRule(
  cwe,
  rule,
  clusterName,
  newTaskDefArn
) {
  const ruleName = rule.Name;
  core.debug(`Looking up Targets for rule ${ruleName}`);

  const data = await cwe
    .listTargetsByRule({
      Rule: ruleName,
    })
    .promise();
  const ruleTargets = data && data.Targets;
  core.debug(`Rule targets for ${ruleName}: ${JSON.stringify(ruleTargets)}`);

  if (!ruleTargets || !ruleTargets.length) return null;

  // Return all targets that are relevant to this cluster.
  const ecsClusterTargets = ecsCwe.filterNonEcsClusterTargets(
    ruleTargets,
    clusterName
  );
  core.debug(
    `ECS ${clusterName} targets for ${ruleName}: ${JSON.stringify(
      ecsClusterTargets
    )}`
  );

  // Of the relevant targets, find the ones whose ARN task matches new ARN (minus version)
  const ecsClusterTaskTargets = ecsCwe.filterUnrelatedTaskDefTargets(
    ecsClusterTargets,
    newTaskDefArn
  );
  core.debug(
    `Task targets for ${ruleName}: ${JSON.stringify(ecsClusterTaskTargets)}`
  );

  // Bail if nothing to update.
  if (!ecsClusterTaskTargets.length) return null;

  // Now we just have to update all the targets that survived.
  const updatedTargets = ecsClusterTaskTargets.map((target) => {
    target.EcsParameters.TaskDefinitionArn = newTaskDefArn;
    return target;
  });
  core.debug(
    `Updated targets for ${ruleName}: ${JSON.stringify(updatedTargets)}`
  );

  return cwe
    .putTargets({
      Rule: ruleName,
      Targets: updatedTargets,
    })
    .promise();
}

function getTaskDefArn(taskDefinitionFile) {
  const taskDefPath = path.isAbsolute(taskDefinitionFile)
    ? taskDefinitionFile
    : path.join(process.env.GITHUB_WORKSPACE, taskDefinitionFile);
  const fileContents = fs.readFileSync(taskDefPath, 'utf8');
  const taskDefinition = yaml.parse(fileContents);
  return taskDefinition.taskDefinitionArn;
}

async function run() {
  try {
    const awsCommonOptions = {
      customUserAgent: 'amazon-ecs-deploy-task-definition-for-github-actions',
    };

    const cwe = new aws.CloudWatchEvents(awsCommonOptions);

    // Get inputs
    const taskDefinitionFile = core.getInput('task-definition', {
      required: true,
    });
    const cluster = core.getInput('cluster', { required: false }) || 'default';
    const rulePrefix = core.getInput('rule-prefix', { required: false }) || '';

    // Get taskDefArn from task definition file
    const taskDefArn = getTaskDefArn(taskDefinitionFile);
    core.setOutput('task-definition-arn', taskDefArn);

    // TODO: Batch this?
    const data = await cwe.listRules().promise();
    const rules = (data && data.Rules) || [];
    await Promise.all(
      rules
        .filter((rule) => {
          return rule.Name.startsWith(rulePrefix);
        })
        .map((rule) => {
          return processCloudwatchEventRule(cwe, rule, cluster, taskDefArn);
        })
    );
  } catch (error) {
    core.setFailed(error.message);
    core.debug(error.stack);
  }
}

module.exports = run;

/* istanbul ignore next */
if (require.main === module) {
  run();
}
