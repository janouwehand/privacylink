import { Routes } from '@angular/router';
import { CreatePage } from './create/create-page';
import { HistoryPage } from './history/history-page';
import { NotFoundPage } from './not-found/not-found-page';
import { PasswordGeneratorPage } from './password-generator/password-generator-page';
import { RecipientPage } from './recipient/recipient-page';
import { SecurityPage } from './security/security-page';
import { SecurityDetailsPage } from './security/security-details-page';
import { StatisticsPage } from './statistics/statistics-page';

export const routes: Routes = [
  { path: '', component: CreatePage },
  { path: 'history', component: HistoryPage },
  { path: 'security', component: SecurityPage },
  { path: 'stats', component: StatisticsPage },
  { path: 'securitydetails', component: SecurityDetailsPage },
  { path: 'passwordgenerator', component: PasswordGeneratorPage },
  { path: 's/:id', component: RecipientPage },
  { path: '**', component: NotFoundPage }
];
