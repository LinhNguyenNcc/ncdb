<script lang="ts" setup>
import { message } from 'ant-design-vue'
import { extractSdkResponseErrorMsg, useApi } from '#imports'

const { api } = useApi()

const { t } = useI18n()

const settings = ref<{ invite_only_signup?: boolean }>({ invite_only_signup: false })

const loadSettings = async () => {
  try {
    const response = await api.orgAppSettings.get()
    settings.value = response
  } catch (e: any) {
    message.error(await extractSdkResponseErrorMsg(e))
  }
}

const saveSettings = async () => {
  try {
    await api.orgAppSettings.set(settings.value)
    message.success(t('msg.success.settingsSaved'))
  } catch (e: any) {
    message.error(await extractSdkResponseErrorMsg(e))
  }
}

loadSettings()
</script>

<template>
  <div data-testid="nc-app-settings">
    <div class="text-xl mt-4 mb-8 text-center font-weight-bold">Settings</div>
    <div class="flex justify-center">
      <a-form-item>
        <a-checkbox
          v-model:checked="settings.invite_only_signup"
          v-e="['c:account:enable-signup']"
          class="nc-checkbox nc-invite-only-signup-checkbox"
          name="virtual"
          @change="saveSettings"
        >
          {{ $t('labels.inviteOnlySignup') }}
        </a-checkbox>
      </a-form-item>
    </div>
  </div>
</template>

<style scoped>
:deep(.ant-checkbox-wrapper) {
  @apply !flex-row-reverse !flex !justify-start gap-4;
  justify-content: flex-start;
}
</style>
